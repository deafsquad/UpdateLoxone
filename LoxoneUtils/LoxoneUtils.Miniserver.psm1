# Module for Loxone Update Script MS Interaction Functions

#region Internal Helper Functions

# Module-level helper function for real-time status updates
# This MUST be at module scope to work in ThreadJob contexts (no closures, no scriptblocks)
function Send-MSStatusUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Updating','Installing','Rebooting','Verifying','Completed','Failed')]
        [string]$State,

        [Parameter(Mandatory=$true)]
        [ValidateRange(0,100)]
        [int]$Progress,

        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [string]$HostForLogging,

        [Parameter(Mandatory=$false)]
        [System.Collections.Concurrent.ConcurrentQueue[hashtable]]$ProgressQueue = $null,

        [Parameter(Mandatory=$false)]
        [System.Collections.ArrayList]$StatusUpdates = $null
    )

    $statusUpdate = @{
        Type = 'Miniserver'  # CRITICAL: Watch-DirectThreadJobs filters on Type='Miniserver'
        State = $State
        Progress = $Progress
        Message = $Message
        Timestamp = Get-Date
        IP = $HostForLogging
    }

    # REAL-TIME: Send to ProgressQueue immediately if provided
    if ($null -ne $ProgressQueue) {
        try {
            [void]$ProgressQueue.Enqueue($statusUpdate)
            Write-Log -Level INFO -Message "[$HostForLogging] REAL-TIME ENQUEUE: $State ($Progress%) - $Message"
        } catch {
            Write-Log -Level WARN -Message "[$HostForLogging] Failed to enqueue real-time status: $_"
        }
    } else {
        Write-Log -Level WARN -Message "[$HostForLogging] ProgressQueue is NULL, cannot send real-time update for $State ($Progress%)"
    }

    # BACKWARD COMPATIBILITY: Collect in ArrayList if provided
    if ($null -ne $StatusUpdates) {
        try {
            [void]$StatusUpdates.Add($statusUpdate)
        } catch {
            Write-Log -Level WARN -Message "[$HostForLogging] Failed to add to StatusUpdates ArrayList: $_"
        }
    }

    # Always log for visibility
    Write-Log -Message "[$HostForLogging] Status update: $State ($Progress%) - $Message" -Level INFO
}

# Wrapper function for Invoke-WebRequest to enable mocking in tests
# Exported to allow mocking from test files
function Invoke-MiniserverWebRequest {
    [CmdletBinding()]
    param(
        [hashtable]$Parameters
    )
    
    # Check if NetworkCore module is available and we're in test mode
    if ((Get-Command Invoke-NetworkRequest -ErrorAction SilentlyContinue) -and 
        ($env:LOXONE_USE_FAST_NETWORK -eq "1" -or $env:PESTER_TEST_RUN -eq "1")) {
        
        # Route through NetworkCore for fast network operations
        try {
            $networkParams = @{
                Uri = $Parameters.Uri
            }
            
            # Convert timeout
            if ($Parameters.TimeoutSec) {
                $networkParams.TimeoutMs = $Parameters.TimeoutSec * 1000
            } else {
                $networkParams.TimeoutMs = 3000  # Default 3 seconds
            }
            
            # Add credentials if present
            if ($Parameters.Credential) {
                $networkParams.Credential = $Parameters.Credential
            }
            
            # Use NetworkCore abstraction
            $result = Invoke-NetworkRequest @networkParams
            
            if ($result.Success) {
                # Return object matching Invoke-WebRequest format
                return [PSCustomObject]@{
                    StatusCode = $result.StatusCode
                    StatusDescription = if ($result.ReasonPhrase) { $result.ReasonPhrase } else { "OK" }
                    Content = if ($result.Content) { $result.Content } else { "" }
                    Headers = @{}
                    RawContent = "HTTP/1.1 $($result.StatusCode) OK`r`n`r`n"
                }
            } else {
                throw $result.Error
            }
        }
        catch {
            # Capture and enhance error details
            $errorMsg = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errorMsg += " | Inner: " + $_.Exception.InnerException.Message
                if ($_.Exception.InnerException.InnerException) {
                    $errorMsg += " | Inner2: " + $_.Exception.InnerException.InnerException.Message
                }
            }
            Write-Log -Level DEBUG -Message "Invoke-MiniserverWebRequest (NetworkCore): $errorMsg"
            throw
        }
    }
    
    # For HTTPS in PowerShell 5.1 with certificate bypass, use HttpWebRequest for reliability
    if ($PSVersionTable.PSVersion.Major -lt 6 -and $Parameters.Uri -like "https://*" -and 
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback) {
        
        # Use HttpWebRequest for better SSL handling in PS 5.1
        try {
            $request = [System.Net.HttpWebRequest]::Create($Parameters.Uri)
            $request.Method = if ($Parameters.Method) { $Parameters.Method } else { "GET" }
            $request.Timeout = if ($Parameters.TimeoutSec) { $Parameters.TimeoutSec * 1000 } else { 100000 }
            
            # Add headers
            if ($Parameters.Headers) {
                foreach ($header in $Parameters.Headers.GetEnumerator()) {
                    if ($header.Key -eq 'Authorization') {
                        $request.Headers.Add($header.Key, $header.Value)
                    } else {
                        $request.Headers[$header.Key] = $header.Value
                    }
                }
            }
            
            # Add credentials if provided
            if ($Parameters.Credential) {
                $request.Credentials = $Parameters.Credential
            }
            
            # Get response
            $response = $request.GetResponse()
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $content = $reader.ReadToEnd()
            
            # Create object similar to Invoke-WebRequest output
            $result = [PSCustomObject]@{
                StatusCode = [int]$response.StatusCode
                StatusDescription = $response.StatusDescription
                Content = $content
                Headers = $response.Headers
                RawContent = "HTTP/1.1 $([int]$response.StatusCode) $($response.StatusDescription)`r`n$($response.Headers.ToString())`r`n`r`n$content"
            }
            
            $reader.Close()
            $response.Close()
            
            return $result
        } catch {
            # Capture and enhance error details for HttpWebRequest
            $errorMsg = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errorMsg += " | Inner: " + $_.Exception.InnerException.Message
                if ($_.Exception.InnerException.InnerException) {
                    $errorMsg += " | Inner2: " + $_.Exception.InnerException.InnerException.Message
                }
            }
            Write-Log -Level DEBUG -Message "Invoke-MiniserverWebRequest (HttpWebRequest): $errorMsg"
            throw
        }
    } elseif ($PSVersionTable.PSVersion.Major -ge 6 -and $Parameters.Uri -like "https://*") {
        # PowerShell 6+ with HTTPS
        # Check if we need to skip certificate validation (for self-signed certs)
        if ([System.Net.ServicePointManager]::ServerCertificateValidationCallback -or 
            $Parameters.ContainsKey('SkipCertificateCheck')) {
            # Certificate validation is bypassed - use SkipCertificateCheck
            $Parameters.Remove('SkipCertificateCheck') | Out-Null
            Invoke-WebRequest @Parameters -SkipCertificateCheck
        } else {
            # Normal HTTPS with valid certificates
            if ($Parameters.ContainsKey('SslProtocol')) {
                $sslValue = $Parameters.SslProtocol
                if ($sslValue -is [array]) {
                    # Already an array, just use it
                    Invoke-WebRequest @Parameters
                } else {
                    # Convert bitmask to array
                    $protocols = @()
                    if ($sslValue -band [System.Net.SecurityProtocolType]::Tls) { $protocols += 'Tls' }
                    if ($sslValue -band [System.Net.SecurityProtocolType]::Tls11) { $protocols += 'Tls11' }
                    if ($sslValue -band [System.Net.SecurityProtocolType]::Tls12) { $protocols += 'Tls12' }
                    try {
                        if ($sslValue -band [System.Net.SecurityProtocolType]::Tls13) { $protocols += 'Tls13' }
                    } catch {
                        # TLS 1.3 not available
                    }
                    $Parameters.Remove('SslProtocol')
                    Invoke-WebRequest @Parameters -SslProtocol $protocols
                }
            } else {
                # Default - just call normally, PS7 will use appropriate TLS
                Invoke-WebRequest @Parameters
            }
        }
    } else {
        # PS 5.1 HTTP requests or PS 6+ without special handling
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
        [int]$TimeoutSec = 3 # Default timeout increased for slow networks
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    Enter-Function -FunctionName $FunctionName -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level DEBUG -Message "Entering function '$($FunctionName)'."
    Write-Log -Level DEBUG -Message "Parameters for '$($FunctionName)':"
    Write-Log -Level DEBUG -Message ("  MSEntry (original): '{0}'" -f ($MSEntry -replace "([Pp]assword=)[^;]+", '$1********'))
    Write-Log -Level DEBUG -Message ("  SkipCertificateCheck: {0}" -f $SkipCertificateCheck.IsPresent)
    Write-Log -Level DEBUG -Message ("  TimeoutSec: {0}" -f $TimeoutSec)
    
    # ConvertTo-SecureString is a built-in cmdlet, no need to import module
    # In parallel execution, importing modules can cause conflicts

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
        
        # Ensure all TLS versions are supported for older Loxone devices
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        } catch {
            # TLS 1.3 might not be available, continue without it
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12
        }

        # Extract only the URL part if entry contains cached data with commas
        # Also check for generation info
        $entryToParse = $MSEntry
        $cachedGeneration = $null
        if ($entryToParse -like '*,*') {
            $parts = $entryToParse.Split(',')
            $entryToParse = $parts[0].Trim()
            Write-Log -Level DEBUG -Message ("$($FunctionName): Extracted URL from cached entry: '{0}'" -f ($entryToParse -replace "([Pp]assword=)[^;]+", '$1********'))
            
            # Check for generation info (4th field)
            if ($parts.Length -ge 4) {
                $cachedGeneration = $parts[3].Trim()
                Write-Log -Level DEBUG -Message ("$($FunctionName): Found cached generation: $cachedGeneration")
            }
        }
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
            try {
                # Ensure ConvertTo-SecureString is available - handle type data conflicts
                if (-not (Get-Command ConvertTo-SecureString -ErrorAction SilentlyContinue)) {
                    Write-Log -Level WARN -Message ("$($FunctionName): ConvertTo-SecureString not available, attempting to import Microsoft.PowerShell.Security module...")
                    try {
                        # First try to remove any conflicting type data
                        $typeData = Get-TypeData -TypeName "System.Security.AccessControl.ObjectSecurity" -ErrorAction SilentlyContinue
                        if ($typeData) {
                            Remove-TypeData -TypeData $typeData -ErrorAction SilentlyContinue
                        }
                        Import-Module Microsoft.PowerShell.Security -Force -DisableNameChecking -ErrorAction Stop
                    } catch {
                        Write-Log -Level ERROR -Message ("$($FunctionName): Failed to import security module: $_")
                        # Fall back to creating credential without ConvertTo-SecureString
                        $credential = $null
                        throw "Security module load failed: $_"
                    }
                }
                
                $securePasswordFromUriBuilder = $uriBuilderForHostAndPath.Password | ConvertTo-SecureString -AsPlainText -Force
                $credential = New-Object System.Management.Automation.PSCredential($uriBuilderForHostAndPath.UserName, $securePasswordFromUriBuilder)
                Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.UserName (for general \$credential obj): '{0}'" -f $uriBuilderForHostAndPath.UserName)
                Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.Password (for general \$credential obj, URL-decoded, length): {0}" -f $uriBuilderForHostAndPath.Password.Length)
                Write-Log -Level DEBUG -Message ("$($FunctionName): General \$credential object created for user: '{0}'" -f $credential.UserName)
            } catch {
                Write-Log -Level ERROR -Message ("$($FunctionName): Failed to create credential object: $_")
                $result.Error = "Failed to create credential: $_"
                return $result
            }
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
        
        # Determine the original scheme early for connectivity checks
        $originalScheme = $uriBuilderForHostAndPath.Scheme
        Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme parsed from MSEntry: '$originalScheme'")
        
        # Check if we can resolve the host first (for better diagnostics)
        if ($msIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            # It's an IP address, try reverse lookup
            try {
                $reverseLookup = [System.Net.Dns]::GetHostEntry($msIP)
                Write-Log -Level DEBUG -Message ("$($FunctionName): Reverse DNS lookup for ${msIP}: $($reverseLookup.HostName)")
            } catch {
                Write-Log -Level DEBUG -Message ("$($FunctionName): Reverse DNS lookup failed for ${msIP}: $_")
            }
            
            # Quick connectivity check
            try {
                # Use NetworkCore for fast connectivity check if available
                if ((Get-Command Test-NetworkEndpoint -ErrorAction SilentlyContinue) -and 
                    ($env:LOXONE_USE_FAST_NETWORK -eq "1" -or $env:PESTER_TEST_RUN -eq "1")) {
                    
                    $port = if ($originalScheme -eq 'https') { 443 } else { 80 }
                    $testUri = "${originalScheme}://${msIP}:${port}"
                    $connectResult = Test-NetworkEndpoint -Uri $testUri -TimeoutMs 100
                    
                    if ($connectResult.Success) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Quick connectivity check passed - port $port is reachable on ${msIP}")
                    } else {
                        Write-Log -Level WARN -Message ("$($FunctionName): Quick connectivity check failed - port $port is NOT reachable on ${msIP} (possible VPN/network issue)")
                    }
                } else {
                    # Fallback to TcpClient for production
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $port = if ($originalScheme -eq 'https') { 443 } else { 80 }
                    $asyncResult = $tcpClient.BeginConnect($msIP, $port, $null, $null)
                    # Increase timeout to 3 seconds for HTTPS (was 1 second)
                    $checkTimeout = if ($originalScheme -eq 'https') { 3000 } else { 1000 }
                    $wait = $asyncResult.AsyncWaitHandle.WaitOne($checkTimeout, $false)
                    
                    if ($wait -and $tcpClient.Connected) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Quick connectivity check passed - port $port is reachable on ${msIP}")
                        $tcpClient.Close()
                    } else {
                        # Downgrade to DEBUG since this is just a quick check and may have false negatives
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Quick connectivity check timed out after ${checkTimeout}ms - port $port on ${msIP}. Will try full connection anyway.")
                        if (-not $wait) { $tcpClient.Close() }
                    }
                }
            } catch {
                Write-Log -Level WARN -Message ("$($FunctionName): Connectivity check error for ${msIP} : $_")
            }
        }
        
        if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
            Write-Log -Level DEBUG -Message ("$($FunctionName): Credentials intended FOR BASIC AUTH HEADER - User: '{0}', Password (literal from input) Length: {1}" -f $usernameForAuthHeader, $passwordForAuthHeader.Length)
        } elseif ($credential) {
             Write-Log -Level DEBUG -Message ("$($FunctionName): General \$credential object exists (user: '{0}'). Manual parsing for Auth header might have been incomplete or not applicable." -f $credential.UserName)
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): No credentials available from manual parsing or UriBuilder for Authorization.")
        }
        if ($SkipCertificateCheck.IsPresent) {
            $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            Set-CertificateValidationBypass
            $callbackChanged = $true
            Write-Log -Message ("Get-MiniserverVersion: SSL certificate check temporarily disabled for {0}." -f $msIP) -Level DEBUG
        }

        $responseObject = $null
        $iwrParams = @{ Uri = $versionUri; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop'; Method = 'Get' }
        if ($credential) { $iwrParams.Credential = $credential }
        
        # Force TLS 1.2 for compatibility with older Miniservers
        if ($originalScheme -eq 'https') {
            $iwrParams.SslProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
        }
        # Add SkipCertificateCheck for PowerShell 6+
        if ($PSVersionTable.PSVersion.Major -ge 6 -and $SkipCertificateCheck.IsPresent) {
            $iwrParams.SkipCertificateCheck = $true
        }

        try { # Main try for Invoke-WebRequest logic
            # Original scheme already determined earlier for connectivity check
            
            # Try NetworkCore first for fast network operations if available
            $responseObject = $null
            if ((Get-Command Invoke-NetworkRequest -ErrorAction SilentlyContinue) -and 
                ($env:LOXONE_USE_FAST_NETWORK -eq "1" -or $env:PESTER_TEST_RUN -eq "1")) {
                
                Write-Log -Level DEBUG -Message ("$($FunctionName): Using NetworkCore for fast network operation")
                
                # Convert timeout to milliseconds for NetworkCore
                # Use shorter timeout in test mode
                $defaultTimeout = if ($env:LOXONE_TEST_MODE -eq "1" -or $env:PESTER_TEST_RUN -eq "1") { 100 } else { 1000 }
                $timeoutMs = if ($TimeoutSec -gt 0) { $TimeoutSec * 1000 } else { $defaultTimeout }
                
                # Build URIs for both protocols
                $httpUri = "http://$msIP/dev/cfg/version"
                $httpsUri = "https://$msIP/dev/cfg/version"
                
                # Try based on original scheme
                $urisToTry = if ($originalScheme -eq 'https') { @($httpsUri) } 
                            elseif ($originalScheme -eq 'http') { @($httpUri) }
                            else { @($httpsUri, $httpUri) }  # Try both if no scheme
                
                foreach ($testUri in $urisToTry) {
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Testing $testUri with NetworkCore (${timeoutMs}ms timeout)")
                    $testResult = Invoke-NetworkRequest -Uri $testUri -TimeoutMs $timeoutMs -Credential $credential -ForceFast
                    
                    if ($testResult.Success -and $testResult.StatusCode -eq 200) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): NetworkCore test successful for $testUri")
                        # Get the actual content using Invoke-MiniserverWebRequest with fast timeout
                        $versionUri = $testUri
                        try {
                            $responseObject = Invoke-MiniserverWebRequest @{
                                Uri = $versionUri
                                Credential = $credential
                                UseBasicParsing = $true
                                TimeoutSec = [Math]::Max(0.1, [Math]::Ceiling($timeoutMs / 1000.0))
                                ErrorAction = 'Stop'
                            }
                            Write-Log -Level DEBUG -Message ("$($FunctionName): Got full response via NetworkCore path")
                            break
                        } catch {
                            Write-Log -Level DEBUG -Message ("$($FunctionName): Failed to get full response after NetworkCore test: $_")
                        }
                    } else {
                        # NetworkCore detected the host is unreachable
                        Write-Log -Level DEBUG -Message ("$($FunctionName): NetworkCore detected unreachable: $($testResult.Error)")
                    }
                }
                
                if (-not $responseObject) {
                    # NetworkCore determined the host is unreachable - don't try standard method
                    Write-Log -Level DEBUG -Message ("$($FunctionName): NetworkCore determined host is unreachable - skipping standard method")
                    $result.Error = "NetworkCore: Host unreachable or timeout after ${timeoutMs}ms"
                    return $result
                }
            }
            
            # If NetworkCore didn't work or isn't available, use standard approach
            if (-not $responseObject) {

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
                # Original entry is HTTPS, use HttpWebRequest for better certificate handling
                Write-Log -Level DEBUG -Message ("$($FunctionName): Original scheme is HTTPS. Using HttpWebRequest method for certificate bypass.")
                
                try {
                    # Create HttpWebRequest for HTTPS with certificate bypass
                    $request = [System.Net.HttpWebRequest]::Create($versionUri)
                    $request.Method = "GET"
                    $request.Timeout = if ($TimeoutSec -gt 0) { $TimeoutSec * 1000 } else { 3000 }
                    
                    # Handle certificate validation bypass for both .NET Framework and .NET Core/5+
                    if ($SkipCertificateCheck) {
                        # For .NET Core/5+, we need to use ServicePointManager
                        if ([System.Net.ServicePointManager].GetProperty('ServerCertificateValidationCallback')) {
                            Set-CertificateValidationBypass
                            Write-Log -Level DEBUG -Message ("$($FunctionName): Set ServicePointManager.ServerCertificateValidationCallback for certificate bypass")
                        }
                        # For older .NET Framework (this property might not work in .NET Core)
                        try {
                            # Skip request-level callback, using global ServicePointManager instead
                            Write-Log -Level DEBUG -Message ("$($FunctionName): Set request.ServerCertificateValidationCallback for certificate bypass")
                        } catch {
                            Write-Log -Level DEBUG -Message ("$($FunctionName): Could not set request.ServerCertificateValidationCallback: $_")
                        }
                    }
                    
                    # Add authentication header if credentials are available
                    if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
                        $authInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${usernameForAuthHeader}:${passwordForAuthHeader}"))
                        $request.Headers.Add("Authorization", "Basic $authInfo")
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Added Basic Auth header for HTTPS request")
                    } elseif ($credential) {
                        $authInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().Password)"))
                        $request.Headers.Add("Authorization", "Basic $authInfo")
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Added Basic Auth header from credential object")
                    }
                    
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Sending HTTPS request to $versionUri with certificate bypass...")
                    
                    # Get the response
                    $httpResponse = $request.GetResponse()
                    $reader = New-Object System.IO.StreamReader($httpResponse.GetResponseStream())
                    $content = $reader.ReadToEnd()
                    
                    # Clean up
                    $reader.Close()
                    $httpResponse.Close()
                    
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS request successful using HttpWebRequest")
                    
                    # Create response object similar to Invoke-WebRequest
                    $responseObject = [PSCustomObject]@{
                        StatusCode = [int]$httpResponse.StatusCode
                        StatusDescription = $httpResponse.StatusDescription
                        Content = $content
                        Headers = $httpResponse.Headers
                    }
                    
                } catch { # Catch for HTTPS HttpWebRequest attempt
                    $CaughtPrimaryHttpsError = $_
                    Write-Log -Level WARN -Message ("$($FunctionName): HTTPS connection to '{0}' failed ('{1}')." -f $versionUri, $CaughtPrimaryHttpsError.Exception.Message.Split([Environment]::NewLine)[0])
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Full Exception for HTTPS failure: $($CaughtPrimaryHttpsError.Exception.ToString())")
                    
                    # Log inner exception for SSL errors with complete detail
                    $currentException = $CaughtPrimaryHttpsError.Exception
                    $exceptionDepth = 0
                    $allExceptions = @()
                    
                    # Traverse all inner exceptions to get the root cause
                    while ($currentException -and $exceptionDepth -lt 10) {
                        $exceptionInfo = @{
                            Type = $currentException.GetType().FullName
                            Message = $currentException.Message
                            Depth = $exceptionDepth
                        }
                        
                        # Check for specific SSL/TLS properties
                        if ($currentException -is [System.Net.WebException]) {
                            $exceptionInfo.Status = $currentException.Status
                            if ($currentException.Response) {
                                $exceptionInfo.ResponseUri = $currentException.Response.ResponseUri
                            }
                        }
                        
                        # Check for authentication exceptions
                        if ($currentException -is [System.Security.Authentication.AuthenticationException]) {
                            $exceptionInfo.AuthType = "AuthenticationException"
                        }
                        
                        $allExceptions += $exceptionInfo
                        $currentException = $currentException.InnerException
                        $exceptionDepth++
                    }
                    
                    # Log the exception chain
                    if ($allExceptions.Count -gt 1) {
                        Write-Log -Level WARN -Message ("$($FunctionName): SSL/TLS Error Chain ($($allExceptions.Count) levels):")
                        foreach ($ex in $allExceptions) {
                            $indent = "  " * $ex.Depth
                            Write-Log -Level WARN -Message ("$($FunctionName): ${indent}[$($ex.Depth)] $($ex.Type): $($ex.Message)")
                            if ($ex.Status) {
                                Write-Log -Level INFO -Message ("$($FunctionName): ${indent}    WebException Status: $($ex.Status)")
                            }
                        }
                        
                        # Log the root cause prominently
                        $rootCause = $allExceptions[-1]
                        Write-Log -Level WARN -Message ("$($FunctionName): ROOT CAUSE: $($rootCause.Type) - $($rootCause.Message)")
                    } else {
                        Write-Log -Level WARN -Message ("$($FunctionName): Single exception: $($allExceptions[0].Type) - $($allExceptions[0].Message)")
                    }
                    
                    # Check if this might be a Gen2 miniserver (they require HTTPS)
                    $isLikelyGen2 = $false
                    
                    # First check cached generation info if available
                    if ($cachedGeneration -eq 'Gen2') {
                        Write-Log -Level INFO -Message ("$($FunctionName): Cached generation info indicates Gen2 miniserver.")
                        $isLikelyGen2 = $true
                    }
                    
                    # Check if the HTTPS error suggests it's actually responding (just with cert issues)
                    if (-not $isLikelyGen2 -and $CaughtPrimaryHttpsError.Exception.Message -match 'SSL|TLS|certificate|handshake') {
                        # The server is responding with HTTPS, just cert issues - might be Gen2
                        Write-Log -Level INFO -Message ("$($FunctionName): HTTPS error suggests server supports HTTPS (SSL/TLS error). May be Gen2 miniserver.")
                        $isLikelyGen2 = $true
                    }
                    
                    if ($isLikelyGen2) {
                        Write-Log -Level WARN -Message ("$($FunctionName): Gen2 miniserver detected. NOT falling back to HTTP for security.")
                        throw $CaughtPrimaryHttpsError
                    }
                    
                    # Try fallback to HTTP only for Gen1 miniservers
                    Write-Log -Level INFO -Message ("$($FunctionName): HTTPS failed, attempting fallback to HTTP (assuming Gen1)...")
                    
                    try {
                        # Build HTTP version of the URI
                        $httpUriBuilder = [System.UriBuilder]$versionUri
                        $httpUriBuilder.Scheme = "http"
                        $httpUriBuilder.Port = 80
                        $httpVersionUri = $httpUriBuilder.Uri.AbsoluteUri
                        
                        Write-Log -Level INFO -Message ("$($FunctionName): Trying HTTP fallback to $httpVersionUri")
                        
                        # Create HTTP request parameters
                        $httpParams = @{ 
                            Uri = $httpVersionUri
                            Method = 'Get'
                            TimeoutSec = $TimeoutSec
                            ErrorAction = 'Stop'
                            UseBasicParsing = $true
                        }
                        
                        # Add authentication if available
                        if (-not [string]::IsNullOrEmpty($usernameForAuthHeader) -and -not [string]::IsNullOrEmpty($passwordForAuthHeader)) {
                            $authInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${usernameForAuthHeader}:${passwordForAuthHeader}"))
                            $httpParams.Headers = @{ Authorization = "Basic $authInfo" }
                        } elseif ($credential) {
                            if ($PSVersionTable.PSVersion.Major -ge 6) {
                                $httpParams.Credential = $credential
                                $httpParams.AllowUnencryptedAuthentication = $true
                            } else {
                                $authInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().Password)"))
                                $httpParams.Headers = @{ Authorization = "Basic $authInfo" }
                            }
                        }
                        
                        $responseObject = Invoke-MiniserverWebRequest -Parameters $httpParams
                        Write-Log -Level INFO -Message ("$($FunctionName): HTTP fallback successful")
                        
                    } catch {
                        $httpFallbackError = $_
                        Write-Log -Level WARN -Message ("$($FunctionName): HTTP fallback also failed: $($httpFallbackError.Exception.Message)")
                        # Throw original HTTPS error as it's more relevant
                        throw $CaughtPrimaryHttpsError
                    }
                }
            } else {
                throw ("$($FunctionName): Unknown original scheme '$originalScheme' from MSEntry '$($entryToParse -replace "([Pp]assword=)[^;]+", '$1********')'")
            } # End of standard approach (if not using NetworkCore)
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
            
            # Add helpful diagnostics for timeout errors
            if ($result.Error -match 'Zeitlimit|Timeout|timed out') {
                Write-Log -Level INFO -Message ("$($FunctionName): Connection timeout for $msIP - this often indicates VPN is down or network connectivity issues")
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
            Clear-CertificateValidationBypass
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
    [decimal]$TimeoutSec = 1 # Default timeout, supports fractional seconds for testing
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

    # Extract only the URL part if entry contains cached data with commas
    $entryToParse = $MSEntry
    if ($entryToParse -like '*,*') {
        $entryToParse = $entryToParse.Split(',')[0].Trim()
        Write-Log -Level DEBUG -Message ("$($FunctionName): Extracted URL from cached entry: '{0}'" -f ($entryToParse -replace "([Pp]assword=)[^;]+", '$1********'))
    }
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
        Set-CertificateValidationBypass
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
             if ($PSVersionTable.PSVersion.Major -ge 6) { 
                 # For PS Core, pass protocols as array
                 try {
                     $iwrParams.SslProtocol = @('Tls', 'Tls11', 'Tls12', 'Tls13')
                 } catch {
                     # TLS 1.3 not available, continue with 1.0/1.1/1.2
                     $iwrParams.SslProtocol = @('Tls', 'Tls11', 'Tls12')
                 }
             }
        }

        try {
            Write-Log -Level DEBUG -Message ("$($FunctionName): iwrParams for ${scheme}: $($iwrParams | Out-String)")
            $responseObject = Invoke-MiniserverWebRequest -Parameters $iwrParams
            Write-Log -Level DEBUG -Message ("$($FunctionName): $scheme connection successful. StatusCode: $($responseObject.StatusCode)")
            $lastException = $null # Clear last exception on success
            break # Success, exit loop
        } catch {
            $lastException = $_
            $errorMsg = $_.Exception.Message
            
            # Capture full error details including inner exceptions
            if ($_.Exception.InnerException) {
                $errorMsg += " | Inner: " + $_.Exception.InnerException.Message
                if ($_.Exception.InnerException.InnerException) {
                    $errorMsg += " | Inner2: " + $_.Exception.InnerException.InnerException.Message
                }
            }
            
            Write-Log -Level WARN -Message ("$($FunctionName): $scheme connection to '$($iwrParams.Uri)' failed: $errorMsg")
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
        Clear-CertificateValidationBypass
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
    # Support all TLS versions for older Loxone devices
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12
    try {
        # Add TLS 1.3 if available
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls13
    } catch {
        # TLS 1.3 not available, continue with 1.0/1.1/1.2
    }

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
            # Extract only the URL part if entry contains cached data with commas
            $entryToParse = $msEntry
            if ($entryToParse -like '*,*') {
                $entryToParse = $entryToParse.Split(',')[0].Trim()
                Write-Log -Level DEBUG -Message ("Update-MS: Extracted URL from cached entry: '{0}'" -f ($entryToParse -replace "([Pp]assword=)[^;]+", '$1********'))
            }
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
                    Set-CertificateValidationBypass; $callbackChangedCheck = $true
                }
    
                try { # For IWR calls
                    # Use shorter timeout in test mode for faster failures
                    $timeoutSeconds = if ($env:LOXONE_USE_FAST_NETWORK -eq "1" -or $env:PESTER_TEST_RUN -eq "1") { 0.1 } else { 3 }
                    $iwrParamsInitialCheck = @{ TimeoutSec = $timeoutSeconds; ErrorAction = 'Stop'; Method = 'Get' }
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
                        if ($PSVersionTable.PSVersion.Major -ge 6) { 
                            # For PS Core, pass protocols as array
                            try {
                                $iwrParamsInitialCheck.SslProtocol = @('Tls', 'Tls11', 'Tls12', 'Tls13')
                            } catch {
                                # TLS 1.3 not available, continue with 1.0/1.1/1.2
                                $iwrParamsInitialCheck.SslProtocol = @('Tls', 'Tls11', 'Tls12')
                            }
                        }
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
                        if ($PSVersionTable.PSVersion.Major -ge 6) { 
                            # For PS Core, pass protocols as array
                            try {
                                $iwrParamsInitialCheck.SslProtocol = @('Tls', 'Tls11', 'Tls12', 'Tls13')
                            } catch {
                                # TLS 1.3 not available, continue with 1.0/1.1/1.2
                                $iwrParamsInitialCheck.SslProtocol = @('Tls', 'Tls11', 'Tls12')
                            }
                        }
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
                if ($callbackChangedCheck) { Clear-CertificateValidationBypass }
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
                # Toast updates are handled by the main thread, not in worker context
                # Progress is reported through return values and callbacks
                
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
    [Parameter()]$PasswordForAuthHeader = $null, # Manually parsed password (can be SecureString or plain text)
    [Parameter()][switch]$SkipCertificateCheck,
    [Parameter()][scriptblock]$ProgressReporter = $null,
    [Parameter()][System.Collections.Concurrent.ConcurrentQueue[hashtable]]$ProgressQueue = $null # REAL-TIME status updates
)
# Immediate defensive check for PS7 parallel context issues
if ($null -eq $MSUri) {
    $invokeResult = [PSCustomObject]@{ VerificationSuccess = $false; ReportedVersion = $null; ErrorOccurredInInvoke = $true; StatusMessage = "MSUri is null" }
    return $invokeResult
}

# Initialize status updates array to collect all state changes
$statusUpdates = [System.Collections.ArrayList]::new()

# Extract IP from URI for logging
$hostForLogging = $null
if ($MSUri) {
    try {
        $uriObj = [System.Uri]$MSUri
        $hostForLogging = $uriObj.Host
    } catch {
        # Fallback to parsing
        if ($MSUri -match '://[^@]+@([^:/]+)') {
            $hostForLogging = $matches[1]
        }
    }
}

# Skip Enter-Function entirely in parallel mode - it uses $MyInvocation which causes issues
if ($env:LOXONE_PARALLEL_MODE -ne "1") {
    try {
        if ($MyInvocation) {
            Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
        }
    } catch {
        # Continue anyway
    }
}

# Log at INFO level to ensure we see it
try {
    # Extra defensive - check if Credential causes issues
    $credInfo = if ($null -eq $Credential) { "null" } else { "present" }
    Write-Log -Level INFO -Message ("Invoke-MSUpdate START - MSUri: '$MSUri', Username: '$UsernameForAuthHeader', Credential: $credInfo")
} catch {
    # Write-Log might fail - but we need to continue
}

# Wrap ALL early parameter checking in try-catch for PS7 parallel issues
try {
    $pwdType = if ($null -eq $PasswordForAuthHeader) { "null" } elseif ($PasswordForAuthHeader -is [System.Security.SecureString]) { "SecureString" } else { "PlainText" }
    Write-Log -Level DEBUG -Message ("Invoke-MSUpdate: UsernameForAuthHeader is null/empty: $([string]::IsNullOrEmpty($UsernameForAuthHeader)), PasswordForAuthHeader type: $pwdType")
    Write-Log -Level DEBUG -Message ("Invoke-MSUpdate: Credential is null: $($null -eq $Credential), MSUri: '$MSUri'")
} catch {
    Write-Log -Level WARN -Message "Failed to check parameter types (expected in PS7 parallel): $_"
}

$invokeResult = [PSCustomObject]@{ 
    VerificationSuccess = $false
    ReportedVersion = $null
    ErrorOccurredInInvoke = $false
    StatusMessage = "NotStarted"
    CurrentState = ''
    LastUpdateStatus = ''
    LastStatusCode = ''
}
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
    
    # Skip progress reporter in parallel context - it causes serialization issues
    # The parallel workflow uses queues for progress instead
    if ($ProgressReporter) {
        try {
            # In parallel context, the ProgressReporter scriptblock may have issues
            # Just log that we're skipping it
            if ($env:LOXONE_PARALLEL_MODE -eq "1") {
                Write-Log -Level DEBUG -Message "Skipping ProgressReporter in parallel context for Invoke-MSUpdate"
            } else {
                # Sequential mode - safe to use
                if ($ProgressReporter -is [scriptblock]) {
                    & $ProgressReporter -Operation "Miniserver Update [$hostForPingInInvoke]" `
                                       -Status "Triggering update" `
                                       -PercentComplete 10 `
                                       -CurrentOperation "Sending update command to miniserver"
                }
            }
        } catch {
            # Progress reporter might fail - continue anyway
            Write-Log -Level DEBUG -Message "ProgressReporter handling failed: $_"
        }
    }

    if ($SkipCertificateCheck.IsPresent) {
        $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        Set-CertificateValidationBypass; $callbackChanged = $true
    }

    # Trigger update with retry logic (5 attempts to allow VPN tunnels time to establish)
    $maxTriggerAttempts = 5
    $triggerAttempt = 0
    $triggerSuccess = $false
    $lastTriggerError = $null
    
    while ($triggerAttempt -lt $maxTriggerAttempts -and -not $triggerSuccess) {
        $triggerAttempt++
        Write-Log -Message ("Trigger attempt {0}/{1} for MS {2}" -f $triggerAttempt, $maxTriggerAttempts, $hostForPingInInvoke) -Level DEBUG
        
        try { # For IWR - Trigger
            # Increase timeout for HTTPS connections which may take longer
            $triggerTimeout = if ($schemeInInvoke -eq 'https') { 15 } else { 10 }
            $triggerParams = @{ Uri = $MSUri; Method = 'Get'; TimeoutSec = $triggerTimeout; ErrorAction = 'Stop' }
            
            # Log credential availability for debugging - be extra defensive for PS7
            $pwdTypeForLog = "unknown"
            try {
                if ($null -eq $PasswordForAuthHeader) { 
                    $pwdTypeForLog = "null" 
                } elseif ($PasswordForAuthHeader) {
                    $pwdTypeForLog = $PasswordForAuthHeader.GetType().Name
                }
            } catch {
                $pwdTypeForLog = "error-checking-type"
            }
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Trigger): Checking credentials - Username: '$UsernameForAuthHeader', Password type: $pwdTypeForLog"
            
            if (-not [string]::IsNullOrEmpty($UsernameForAuthHeader) -and ($PasswordForAuthHeader -ne $null)) {
                Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Trigger): Using manually parsed credentials for Authorization header."
                $plainPasswordForAuthHeader = $null
                
                # Handle both SecureString and plain text password
                if ($PasswordForAuthHeader -is [System.Security.SecureString]) {
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
                } else {
                    # Already plain text
                    $plainPasswordForAuthHeader = $PasswordForAuthHeader
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
                    if ($Credential) {
                        $UsernameDecoded = $Credential.UserName; $PasswordDecoded = $Credential.GetNetworkCredential().Password
                    } else {
                        Write-Log -Level ERROR -Message "Invoke-MSUpdate (Trigger): Credential object is null when trying to extract username/password for HTTP"
                        throw "No credentials available for authentication"
                    }
                    Write-Log -Level WARN -Message "Invoke-MSUpdate (Trigger): PS5 HTTP with \$Credential. Password used will be URL-decoded from \$Credential object."
                    $EncodedCredentialsDecoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${UsernameDecoded}:${PasswordDecoded}"))
                    $triggerParams.Headers = @{ Authorization = "Basic $EncodedCredentialsDecoded" }
                } else { # HTTPS
                    if ($Credential) {
                        $triggerParams.Credential = $Credential
                    } else {
                        Write-Log -Level ERROR -Message "Invoke-MSUpdate (Trigger): HTTPS connection but Credential object is null"
                        throw "No credentials available for HTTPS authentication to miniserver"
                    }
                }
            } else {
                # No credentials at all - this is fatal for HTTPS
                if ($schemeInInvoke -eq 'https') {
                    Write-Log -Level ERROR -Message "Invoke-MSUpdate (Trigger): HTTPS connection to '$hostForPingInInvoke' but NO credentials available (neither manual nor Credential object)"
                    throw "HTTPS connection requires credentials but none were provided for $hostForPingInInvoke"
                }
                Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Trigger): No credentials provided."
            }
            if ($schemeInInvoke -eq 'http') { $triggerParams.UseBasicParsing = $true }
    
            Write-Log -Level DEBUG -Message ("Invoke-MSUpdate (Trigger): triggerParams before invoke: $($triggerParams | Out-String)")
            
            # Log that we're triggering the update
            Write-Log -Message ("TRIGGERING UPDATE for MS {0} to version {1}" -f $hostForPingInInvoke, $NormalizedDesiredVersion) -Level INFO
            
            $triggerResponse = Invoke-MiniserverWebRequest -Parameters $triggerParams
            Write-Log -Message ("Trigger response from MS {0}: StatusCode={1}, ContentLength={2}" -f $hostForPingInInvoke, $triggerResponse.StatusCode, ($triggerResponse.Content | Measure-Object -Character).Characters) -Level INFO
            Write-Log -Message ("Trigger response body from MS {0}: {1}" -f $hostForPingInInvoke, ($triggerResponse.Content -replace '\s+', ' ').Trim()) -Level INFO

            # Verify trigger response - check HTTP status and XML Code attribute
            $triggerVerified = $false
            $triggerFailReason = ""
            if (-not $triggerResponse) {
                $triggerFailReason = "No response received from Miniserver"
            } elseif ($triggerResponse.StatusCode -ne 200) {
                $triggerFailReason = "HTTP StatusCode=$($triggerResponse.StatusCode) (expected 200)"
            } elseif (-not $triggerResponse.Content) {
                $triggerFailReason = "Empty response body"
            } else {
                # Parse XML Code attribute from response: <LL control="dev/sys/autoupdate" value="" Code="200"/>
                if ($triggerResponse.Content -match 'Code="(\d+)"') {
                    $xmlCode = $Matches[1]
                    if ($xmlCode -eq '200') {
                        $triggerVerified = $true
                    } else {
                        $triggerFailReason = "Miniserver returned Code=$xmlCode (expected 200)"
                    }
                } else {
                    # No Code attribute found - could be unexpected response format
                    Write-Log -Message ("Trigger response from MS {0}: No Code attribute in response, treating as accepted (body: {1})" -f $hostForPingInInvoke, ($triggerResponse.Content -replace '\s+', ' ').Trim()) -Level WARN
                    $triggerVerified = $true
                }
            }

            if ($triggerVerified) {
                Write-Log -Message ("UPDATE COMMAND ACCEPTED by '{0}'. Miniserver is starting update process to version {1}." -f $hostForPingInInvoke, $NormalizedDesiredVersion) -Level INFO
                $invokeResult.StatusMessage = "UpdateAccepted_ProcessStarting"

                # Add status update that update was triggered (REAL-TIME)
                Send-MSStatusUpdate -State 'Updating' -Progress 30 -Message "Update triggered" `
                    -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates

                # Initialize status tracking variables for polling
                $script:LastLoggedStatus = $null
                $script:LastStatusMessage = $null

                # Report progress with more accurate status
                if ($ProgressReporter) {
                    & $ProgressReporter -Operation "Miniserver Update [$hostForPingInInvoke]" `
                                       -Status "Update accepted - Process starting" `
                                       -PercentComplete 25 `
                                       -CurrentOperation "Miniserver confirmed update and is preparing"
                }

                # Mark trigger as successful
                $triggerSuccess = $true
                Write-Log -Message ("Trigger attempt {0} succeeded for MS {1}" -f $triggerAttempt, $hostForPingInInvoke) -Level DEBUG
            } else {
                Write-Log -Message ("UPDATE COMMAND REJECTED/FAILED for MS {0}: {1}" -f $hostForPingInInvoke, $triggerFailReason) -Level WARN
                $invokeResult.StatusMessage = "UpdateTriggerFailed"
                $invokeResult.TriggerFailReason = $triggerFailReason
            }
            
        } catch {
            $CaughtError = $_
            $lastTriggerError = $CaughtError
            Write-Log -Message ("Trigger attempt {0}/{1} failed for '{2}': {3}" -f $triggerAttempt, $maxTriggerAttempts, $hostForPingInInvoke, $CaughtError.Exception.Message) -Level WARN
            
            # If not the last attempt, wait before retrying
            if ($triggerAttempt -lt $maxTriggerAttempts) {
                $retryDelay = 2 * $triggerAttempt  # Progressive delay: 2s, 4s, 6s
                Write-Log -Message ("Waiting {0} seconds before retry..." -f $retryDelay) -Level DEBUG
                Start-Sleep -Seconds $retryDelay
            }
        }
    }  # End of retry while loop
    } catch {
        # Catch for the outer try block at line 1398
        $triggerError = $_
        Write-Log -Message ("Failed to trigger update for MS {0}: {1}" -f $hostForPingInInvoke, $triggerError) -Level ERROR
        $invokeResult.StatusMessage = "Failed to trigger update: $triggerError"
        $invokeResult.Success = $false
    }

    # Check if trigger was successful after all attempts
    if (-not $triggerSuccess) {
        $invokeResult.ErrorOccurredInInvoke = $true
        $invokeResult.StatusMessage = ("Error_TriggeringUpdate: {0}" -f $lastTriggerError.Exception.Message.Split([Environment]::NewLine)[0])
        Write-Log -Message ("All {0} trigger attempts failed for '{1}': {2}" -f $maxTriggerAttempts, $hostForPingInInvoke, $lastTriggerError.Exception.Message) -Level ERROR
    }

    if (-not $invokeResult.ErrorOccurredInInvoke) {
        Write-Log -Message ("Waiting for MS {0} to reboot/update..." -f $hostForPingInInvoke) -Level INFO
        # Progress reporting is handled through ProgressReporter callback, not direct toast updates
        
        # Initialize detailed stage tracking
        $stageStartTime = Get-Date
        $currentStage = "Initializing"
        $stageHistory = @()
        
        $startTime = Get-Date; $timeout = New-TimeSpan -Minutes 15; $msResponsive = $false; $loggedUpdatingStatus = $false
        $verifyParams = @{ Uri = $verificationUriForPolling; UseBasicParsing = $true; TimeoutSec = 3; ErrorAction = 'Stop' }
        
        # Add SkipCertificateCheck for HTTPS verification if needed (same as trigger)
        if ($schemeInInvoke -eq 'https' -and $SkipCertificateCheck.IsPresent -and $PSVersionTable.PSVersion.Major -ge 6) {
            $verifyParams.SkipCertificateCheck = $true
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Polling): Added SkipCertificateCheck for HTTPS verification"
        }

        if (-not [string]::IsNullOrEmpty($UsernameForAuthHeader) -and ($PasswordForAuthHeader -ne $null)) {
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Polling): Using manually parsed credentials for Authorization header."
            $plainPasswordForVerifyHeader = $null
            
            # Handle both SecureString and plain text password
            if ($PasswordForAuthHeader -is [System.Security.SecureString]) {
                $bstrVerify = $null
                try {
                    # Convert SecureString to plain text for the Authorization header
                    $bstrVerify = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordForAuthHeader)
                    $plainPasswordForVerifyHeader = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrVerify)
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to convert SecureString for verification: $_"
                    throw
                }
                finally {
                    If ($null -ne $bstrVerify) {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrVerify)
                    }
                }
            } else {
                # Already plain text
                $plainPasswordForVerifyHeader = $PasswordForAuthHeader
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
                if ($Credential) {
                    $UsernameDecodedPoll = $Credential.UserName; $PasswordDecodedPoll = $Credential.GetNetworkCredential().Password
                } else {
                    Write-Log -Level ERROR -Message "Invoke-MSUpdate (Polling): HTTP connection but Credential object is null"
                    throw "No credentials available for HTTP authentication during polling"
                }
                Write-Log -Level WARN -Message "Invoke-MSUpdate (Polling): PS5 HTTP with \$Credential. Password used will be URL-decoded from \$Credential object."
                $EncodedCredentialsDecodedPoll = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${UsernameDecodedPoll}:${PasswordDecodedPoll}"))
                $verifyParams.Headers = @{ Authorization = "Basic $EncodedCredentialsDecodedPoll" }
            } else { # HTTPS
                if ($Credential) {
                    $verifyParams.Credential = $Credential
                } else {
                    Write-Log -Level ERROR -Message "Invoke-MSUpdate (Polling): HTTPS connection but Credential object is null"
                    throw "No credentials available for HTTPS authentication during polling"
                }
            }
        } else {
            Write-Log -Level DEBUG -Message "Invoke-MSUpdate (Polling): No credentials provided."
        }
        # UseBasicParsing is already in $verifyParams base definition for polling.
        Write-Log -Level DEBUG -Message ("Invoke-MSUpdate (Polling): verifyParams before invoke: $($verifyParams | Out-String)")

        $Attempts = 0; $MaxAttempts = [Math]::Floor($timeout.TotalSeconds / 10)
        $LastPollStatusMessage = "Initiating..."
        $LastStageCode = ""
        Write-Log -Message ("Starting polling loop for MS {0}, MaxAttempts: {1}, Timeout: {2} minutes" -f $hostForPingInInvoke, $MaxAttempts, $timeout.TotalMinutes) -Level INFO
        
        # Log initial stage with timestamp
        $stageEntry = @{
            Stage = $currentStage
            StartTime = $stageStartTime
            ElapsedMs = 0
        }
        $stageHistory += $stageEntry
        Write-Log -Message ("[STAGE] MS {0} - Stage: {1} - Time: {2:yyyy-MM-dd HH:mm:ss.fff}" -f $hostForPingInInvoke, $currentStage, $stageStartTime) -Level INFO
        
        # Report initial progress with stage info
        if ($ProgressReporter) {
            & $ProgressReporter -Operation "Miniserver Update [$hostForPingInInvoke]" `
                               -Status "Waiting for miniserver to reboot - Stage: $currentStage" `
                               -PercentComplete 30 `
                               -CurrentOperation "Starting update monitoring | Polling interval: 10s"
        }
        $updateCompleted = $false  # Flag to track when update is successfully verified
        while (((Get-Date) - $startTime) -lt $timeout) {
            $Attempts++
            # In ThreadJob context, Write-Host doesn't work properly, use logging instead
            Write-Log -Message ("Polling MS {0} (Attempt {1}/{2}): {3}" -f $hostForPingInInvoke, $Attempts, $MaxAttempts, $LastPollStatusMessage) -Level INFO
            Start-Sleep -Seconds 10

            try {
            # Add retry logic for each poll attempt
            $pollRetryCount = 0
            $maxPollRetries = 3
            $pollSucceeded = $false

            while ($pollRetryCount -lt $maxPollRetries -and -not $pollSucceeded) {
                try {
                    if ($pollRetryCount -gt 0) {
                        Write-Log -Message ("Retrying poll attempt {0} (retry {1}/{2})" -f $Attempts, $pollRetryCount, $maxPollRetries) -Level INFO
                        Start-Sleep -Seconds 2
                    }

                    Write-Log -Message ("Calling Invoke-MiniserverWebRequest for poll attempt {0}" -f $Attempts) -Level INFO
                    $lastResponse = Invoke-MiniserverWebRequest -Parameters $verifyParams
                    Write-Log -Message ("Poll response received, parsing XML..." -f $Attempts) -Level INFO
                    $msResponsive = $true; $xmlCurrent = [xml]$lastResponse.Content; $versionCurrentPoll = $xmlCurrent.LL.value
                    $pollSucceeded = $true
                    if ([string]::IsNullOrEmpty($versionCurrentPoll)) { throw "LL.value empty in poll response." }
                    $normalizedVersionCurrentPoll = Convert-VersionString $versionCurrentPoll; $invokeResult.ReportedVersion = $normalizedVersionCurrentPoll

                    # Add Verifying status if MS just came back from reboot (before checking version)
                    if ($script:RebootDetected -and -not $script:VerificationDetected) {
                        Write-Log -Level INFO -Message ("[STATE_CHANGE] MS {0} responsive after reboot - entering verification phase" -f $hostForPingInInvoke)
                        $script:VerificationDetected = $true

                        # Add verification state update (REAL-TIME)
                        Send-MSStatusUpdate -State 'Verifying' -Progress 85 -Message "Verifying update" `
                            -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                    }

                    if ($normalizedVersionCurrentPoll -eq $NormalizedDesiredVersion) {
                    $invokeResult.VerificationSuccess = $true; $invokeResult.StatusMessage = "UpdateSuccessful_VersionVerified"; $LastPollStatusMessage = ("OK - Version {0}" -f $NormalizedDesiredVersion)
                    
                    # Log final stage completion
                    $finalDuration = ((Get-Date) - $stageStartTime).TotalMilliseconds
                    Write-Log -Message ("[STAGE_COMPLETE] MS {0} - Final stage: '{1}' - Duration: {2:N0}ms" -f $hostForPingInInvoke, $currentStage, $finalDuration) -Level INFO
                    
                    # Log summary of all stages
                    $totalUpdateDuration = ((Get-Date) - $startTime).TotalSeconds
                    Write-Log -Message ("[UPDATE_SUMMARY] MS {0} - Total update time: {1:N1} seconds - Stages completed: {2}" -f $hostForPingInInvoke, $totalUpdateDuration, $stageHistory.Count) -Level INFO
                    
                    if ($stageHistory.Count -gt 1) {
                        foreach ($stage in $stageHistory) {
                            if ($stage.PreviousStageDuration) {
                                Write-Log -Message ("  - Stage '{0}': {1:N0}ms" -f $stage.PreviousStage, $stage.PreviousStageDuration) -Level INFO
                            }
                        }
                    }
                    
                    # Log successful update completion
                    Write-Log -Message ("UPDATE SUCCESSFUL for MS {0}: Now running version {1}" -f $hostForPingInInvoke, $NormalizedDesiredVersion) -Level INFO
                    
                    # Add status update for successful verification (REAL-TIME)
                    Send-MSStatusUpdate -State 'Completed' -Progress 100 -Message "Updated to $NormalizedDesiredVersion" `
                        -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                    
                    # Success is reported through ProgressReporter, not direct toast updates
                    
                    # Report success with complete timing summary
                    if ($ProgressReporter) {
                        $totalDuration = ((Get-Date) - $startTime).TotalSeconds
                        $summaryText = "Update completed in {0:N1} seconds | {1} stages" -f $totalDuration, $stageHistory.Count
                        & $ProgressReporter -Operation "Miniserver Update [$hostForPingInInvoke]" `
                                           -Status "Update completed successfully" `
                                           -PercentComplete 100 `
                                           -CurrentOperation "Version verified: $NormalizedDesiredVersion | $summaryText"
                    }
                    $updateCompleted = $true  # Set flag to exit outer polling loop
                    break
                } else {
                    $invokeResult.StatusMessage = ("Polling_VersionMismatch_Current_{0}" -f $normalizedVersionCurrentPoll)
                    $LastPollStatusMessage = ("OK - Version {0} (Expected {1})" -f $normalizedVersionCurrentPoll, $NormalizedDesiredVersion)
                    # Log version mismatch during polling
                    Write-Log -Level INFO -Message ("MS {0} responded with version {1}, still waiting for {2}" -f $hostForPingInInvoke, $normalizedVersionCurrentPoll, $NormalizedDesiredVersion)
                }
                }
                catch [System.Net.WebException] {
                    # Handle 503 responses (MS updating) - parse response body BEFORE throwing
                    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 503) {
                        # Parse the 503 response body to extract detailed status code
                        $parsedErrorDetail = 'Updating...'
                        try {
                            $responseStream = $_.Exception.Response.GetResponseStream()
                            $streamReader = New-Object System.IO.StreamReader($responseStream)
                            $responseBody = $streamReader.ReadToEnd()
                            $streamReader.Close()
                            $responseStream.Close()

                            Write-Log -Level DEBUG -Message ("MS {0} 503 response body: '{1}'" -f $hostForPingInInvoke, $responseBody)

                            # Extract error detail code (530-534)
                            if ($responseBody -match '<errordetail>(.*?)</errordetail>') {
                                $parsedErrorDetail = $matches[1].Trim()
                                Write-Log -Level INFO -Message ("MS {0} 503 status code: '{1}'" -f $hostForPingInInvoke, $parsedErrorDetail)
                            }
                        } catch {
                            Write-Log -Level DEBUG -Message ("MS {0} failed to parse 503 body: {1}" -f $hostForPingInInvoke, $_)
                        }

                        # Store the parsed error detail in the exception for outer catch
                        $_.Exception | Add-Member -NotePropertyName 'ParsedErrorDetail' -NotePropertyValue $parsedErrorDetail -Force -ErrorAction SilentlyContinue

                        # Let the outer catch block handle 503 responses
                        throw
                    }

                    # For other web exceptions, retry
                    $pollRetryCount++
                    if ($pollRetryCount -ge $maxPollRetries) {
                        Write-Log -Message ("Poll attempt {0} failed after {1} retries: {2}" -f $Attempts, $pollRetryCount, $_.Exception.Message) -Level WARN
                        throw
                    }
                    Write-Log -Message ("Poll attempt {0} retry {1} failed: {2}" -f $Attempts, $pollRetryCount, $_.Exception.Message) -Level DEBUG
                } catch {
                    # For non-web exceptions, retry
                    $pollRetryCount++
                    if ($pollRetryCount -ge $maxPollRetries) {
                        Write-Log -Message ("Poll attempt {0} failed after {1} retries: {2}" -f $Attempts, $pollRetryCount, $_) -Level WARN
                        throw
                    }
                    Write-Log -Message ("Poll attempt {0} retry {1} failed: {2}" -f $Attempts, $pollRetryCount, $_) -Level DEBUG
                }

            # If all retries failed, handle the exception
            if (-not $pollSucceeded) {
                # Continue to the next iteration of the outer while loop
                continue
            }
            } # End of retry while loop

            # Check if update was successfully verified - if so, exit the outer polling loop
            if ($updateCompleted) {
                Write-Log -Message "Update successfully verified for MS $hostForPingInInvoke - exiting polling loop" -Level INFO
                break
            }

            } # End of outer try
            catch [System.Net.WebException] {
                $CaughtWebError = $_
                $statusCode = if ($CaughtWebError.Exception.Response) { [int]$CaughtWebError.Exception.Response.StatusCode } else { $null }
                if ($statusCode -eq 503) {
                    $invokeResult.StatusMessage = "Polling_MS_Updating_503"

                    # Use the pre-parsed error detail from the inner catch
                    $errorDetail = if ($CaughtWebError.Exception.ParsedErrorDetail) {
                        $CaughtWebError.Exception.ParsedErrorDetail
                    } else {
                        'Updating...'
                    }

                    Write-Log -Level DEBUG -Message ("MS {0} using parsed error detail: '{1}'" -f $hostForPingInInvoke, $errorDetail)

                    # Store the raw status code
                    $invokeResult.LastStatusCode = $errorDetail

                    # Parse status codes for more user-friendly messages
                    $statusMessage = switch -Regex ($errorDetail) {
                        '530' { "Downloading update files" }
                        '531' { "Preparing update installation" }
                        '532' { "Installing update" }
                        '533' { "Finalizing update" }
                        '534' { "Rebooting miniserver" }
                        'Updating' { "Update in progress" }
                        default { $errorDetail }
                    }

                    # Track stage changes with millisecond precision
                    if ($errorDetail -ne $LastStageCode) {
                        $previousStage = $currentStage
                        $currentStage = $statusMessage
                        $newStageTime = Get-Date
                        $stageDuration = ($newStageTime - $stageStartTime).TotalMilliseconds

                        # Log stage transition with detailed timing
                        Write-Log -Message ("[STAGE_TRANSITION] MS {0} - From: '{1}' to '{2}' - Duration: {3:N0}ms - Time: {4:yyyy-MM-dd HH:mm:ss.fff}" -f $hostForPingInInvoke, $previousStage, $currentStage, $stageDuration, $newStageTime) -Level INFO

                        # Add to stage history
                        $stageEntry = @{
                            Stage = $currentStage
                            StatusCode = $errorDetail
                            StartTime = $newStageTime
                            PreviousStage = $previousStage
                            PreviousStageDuration = $stageDuration
                        }
                        $stageHistory += $stageEntry

                        # Update stage tracking
                        $stageStartTime = $newStageTime
                        $LastStageCode = $errorDetail

                        # Send detailed progress update if available
                        if ($ProgressQueue) {
                            $detailedProgress = @{
                                Type = 'StageTransition'
                                MiniserverIP = $hostForPingInInvoke
                                Stage = $currentStage
                                StatusCode = $errorDetail
                                Timestamp = $newStageTime
                                ElapsedMs = $stageDuration
                                Attempt = $Attempts
                            }
                            try {
                                [void]$ProgressQueue.Enqueue($detailedProgress)
                                Write-Log -Message ("[PROGRESS_NOTIFICATION] Sent stage transition notification for MS {0}: {1}" -f $hostForPingInInvoke, $currentStage) -Level DEBUG
                            } catch {
                                Write-Log -Message "Failed to send stage transition progress: $_" -Level WARN
                            }
                        }
                    }

                    # If no specific error detail code was found, use timing-based state detection
                    if ($errorDetail -eq 'Updating...' -or -not ($errorDetail -match '^\d{3}$')) {
                        Write-Log -Level INFO -Message ("MS {0} 503 without error detail. Using timing-based state detection (poll #{1})" -f $hostForPingInInvoke, $Attempts)

                        # Estimate state based on timing (typical update sequence)
                        $elapsedSinceStart = ((Get-Date) - $startTime).TotalSeconds
                        $estimatedState = if ($elapsedSinceStart -lt 30) {
                            "Downloading update"  # First 30 seconds
                        } elseif ($elapsedSinceStart -lt 90) {
                            "Installing update"   # 30-90 seconds
                        } elseif ($elapsedSinceStart -lt 180) {
                            "Rebooting"          # 90-180 seconds (includes unreachable period)
                        } elseif ($elapsedSinceStart -lt 240) {
                            "Verifying"          # 180-240 seconds
                        } else {
                            "Update in progress" # Beyond 240 seconds
                        }

                        $statusMessage = $estimatedState
                        $errorDetail = "503-Estimated"

                        # Track estimated state changes
                        if ($estimatedState -ne $script:LastEstimatedState) {
                            Write-Log -Level INFO -Message ("[ESTIMATED_STATE] MS {0} - State: '{1}' after {2:N0} seconds" -f $hostForPingInInvoke, $estimatedState, $elapsedSinceStart)
                            $script:LastEstimatedState = $estimatedState

                            # Send progress update for estimated state
                            $newState = switch ($estimatedState) {
                                "Downloading update" { 'Downloading' }
                                "Installing update" { 'Installing' }
                                "Rebooting" { 'Rebooting' }
                                "Verifying" { 'Verifying' }
                                default { 'Updating' }
                            }

                            $progressValue = switch ($newState) {
                                'Downloading' { 35 }
                                'Installing' { 50 }
                                'Rebooting' { 65 }
                                'Verifying' { 80 }
                                default { 45 }
                            }

                            # Add estimated state update (REAL-TIME)
                            Send-MSStatusUpdate -State $newState -Progress $progressValue -Message $statusMessage `
                                -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                        }
                    }
                    
                    $LastPollStatusMessage = ("Updating: {0}" -f $statusMessage)
                    
                    # Track the update state for return value
                    $newState = ''
                    $progressValue = 40
                    if ($errorDetail -eq '534') {
                        $invokeResult.CurrentState = 'Rebooting'
                        $newState = 'Rebooting'
                        $progressValue = 60
                    } elseif ($errorDetail -match '^53[0-3]$') {
                        $invokeResult.CurrentState = 'Installing'
                        $newState = 'Installing'
                        $progressValue = 50
                    } else {
                        $invokeResult.CurrentState = 'Updating'
                        $newState = 'Updating'
                        $progressValue = 45
                    }
                    $invokeResult.LastUpdateStatus = $statusMessage
                    
                    # Log every status during polling to track all changes
                    if (-not $loggedUpdatingStatus) { 
                        # First status detected
                        Write-Log -Level INFO -Message ("MS {0} initial update status: {1} (Status Code: {2})" -f $hostForPingInInvoke, $statusMessage, $errorDetail)
                        $loggedUpdatingStatus = $true
                        $script:LastLoggedStatus = $errorDetail
                        $script:LastStatusMessage = $statusMessage
                        
                        # Add initial status update (REAL-TIME)
                        Send-MSStatusUpdate -State $newState -Progress $progressValue -Message $statusMessage `
                            -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                        
                    } elseif ($script:LastLoggedStatus -ne $errorDetail) {
                        # Status has changed - log it and send real-time update
                        Write-Log -Level INFO -Message ("MS {0} STATUS CHANGE: {1} (Code: {2}, Previous Code: {3})" -f $hostForPingInInvoke, $statusMessage, $errorDetail, $script:LastLoggedStatus)
                        $script:LastLoggedStatus = $errorDetail
                        $script:LastStatusMessage = $statusMessage
                        
                        # Add status change update (REAL-TIME)
                        Send-MSStatusUpdate -State $newState -Progress $progressValue -Message $statusMessage `
                            -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                        
                    } else {
                        # Same status - always log it to track all polling attempts
                        Write-Log -Level INFO -Message ("MS {0} poll #{1}: {2} (Code: {3})" -f $hostForPingInInvoke, $Attempts, $statusMessage, $errorDetail)
                    }
                    
                    # Report update progress with detailed status and timing
                    if ($ProgressReporter) {
                        $stageDurationText = if ($stageHistory.Count -gt 0) {
                            $totalElapsed = ((Get-Date) - $startTime).TotalSeconds
                            $stageElapsed = ((Get-Date) - $stageStartTime).TotalSeconds
                            " | Stage: {0:N0}s / Total: {1:N0}s" -f $stageElapsed, $totalElapsed
                        } else { "" }
                        
                        $percentComplete = 40 + [Math]::Min(50, [Math]::Round(($Attempts / $MaxAttempts) * 50, 0))
                        & $ProgressReporter -Operation "Miniserver Update [$hostForPingInInvoke]" `
                                           -Status ($statusMessage + $stageDurationText) `
                                           -PercentComplete $percentComplete `
                                           -CurrentOperation "Status Code: $errorDetail | Attempt: $Attempts/$MaxAttempts"
                    }
                } else { $invokeResult.StatusMessage = ("Polling_WebException_StatusCode_{0}" -f $statusCode); $LastPollStatusMessage = ("Error ({0})" -f $statusCode) }
                Write-Log -Message ("MS {0} WebException during poll ({1}): {2}" -f $hostForPingInInvoke, $LastPollStatusMessage, $CaughtWebError.Exception.Message.Split([Environment]::NewLine)[0]) -Level WARN
            }
            catch {
            $CaughtCatchError = $_
            # Check if this is an HTTP error that contains a 503 status
            if ($CaughtCatchError.Exception.Message -match '503' -or $CaughtCatchError.Exception.Message -match 'Service Unavailable' -or $CaughtCatchError.Exception.Message -match 'Miniserver Updating') {
                # This is likely a 503 error during update
                $invokeResult.StatusMessage = "Polling_MS_Updating_503"
                $LastPollStatusMessage = "Updating (503)"
                
                # Try to extract status from error message
                $statusMessage = "Update in progress"
                if ($CaughtCatchError.Exception.Message -match 'Miniserver Updating') {
                    $statusMessage = "Miniserver updating"
                }
                
                # Track as updating state
                $invokeResult.CurrentState = 'Updating'
                $invokeResult.LastUpdateStatus = $statusMessage
                
                Write-Log -Level INFO -Message ("MS {0} returned 503 during poll #{1}: {2}" -f $hostForPingInInvoke, $Attempts, $CaughtCatchError.Exception.Message)
                
                # Log status change if needed and send real-time update
                if (-not $loggedUpdatingStatus) {
                    Write-Log -Level INFO -Message ("MS {0} initial update status detected via 503 error" -f $hostForPingInInvoke)
                    $loggedUpdatingStatus = $true
                    $script:LastStatusMessage = $statusMessage
                    
                    # Add status update for 503 (updating) (REAL-TIME)
                    Send-MSStatusUpdate -State 'Updating' -Progress 45 -Message $statusMessage `
                        -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                }
            } else {
                # Regular connection/parse error - likely rebooting if we had 503s before
                $invokeResult.StatusMessage = ("Polling_Unreachable_Or_ParseError: {0}" -f $CaughtCatchError.Exception.Message.Split([Environment]::NewLine)[0])
                $LastPollStatusMessage = "Unreachable/ParseError"
                Write-Log -Message ("MS {0} unreachable/parse error: {1}" -f $hostForPingInInvoke, $CaughtCatchError.Exception.Message) -Level WARN
                
                # If we previously had 503 responses and now unreachable, it's likely rebooting
                if ($loggedUpdatingStatus -and -not $script:RebootDetected) {
                    Write-Log -Level INFO -Message ("[STATE_CHANGE] MS {0} became unreachable after update - likely rebooting" -f $hostForPingInInvoke)
                    $script:RebootDetected = $true
                    
                    # Add reboot state update (REAL-TIME)
                    Send-MSStatusUpdate -State 'Rebooting' -Progress 70 -Message "Miniserver rebooting" `
                        -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
                }
            }
        }
    } # End while
    Write-Log -Message ("Polling loop ended for MS {0}. Success: {1}, Final status: {2}" -f $hostForPingInInvoke, $invokeResult.VerificationSuccess, $LastPollStatusMessage) -Level INFO
    if (-not $invokeResult.VerificationSuccess) {
        if ($msResponsive) { $invokeResult.StatusMessage = ("VerificationFailed_Timeout_VersionMismatch_FinalReported_{0}" -f $invokeResult.ReportedVersion) }
        else { $invokeResult.StatusMessage = "VerificationFailed_Timeout_NoResponse" }
        Write-Log -Message ("FAILURE: MS {0} - {1}" -f $hostForPingInInvoke, $invokeResult.StatusMessage) -Level ERROR
        
        # Add failure status update (REAL-TIME)
        $failureMsg = if ($msResponsive) { "Update timeout - version mismatch" } else { "No response from miniserver" }
        Send-MSStatusUpdate -State 'Failed' -Progress 0 -Message $failureMsg `
            -HostForLogging $hostForLogging -ProgressQueue $ProgressQueue -StatusUpdates $statusUpdates
        
        # Failure is reported through ProgressReporter, not direct toast updates
    }

    # Add collected status updates to the result
    $invokeResult | Add-Member -NotePropertyName 'StatusUpdates' -NotePropertyValue $statusUpdates -Force

    # Debug log the status updates being returned
    Write-Log -Message "Invoke-MSUpdate returning with $($statusUpdates.Count) status updates for MS $hostForLogging" -Level "INFO"
    if ($statusUpdates.Count -gt 0) {
        foreach ($update in $statusUpdates) {
            Write-Log -Message "  - StatusUpdate: State=$($update.State), Progress=$($update.Progress), Message=$($update.Message)" -Level "DEBUG"
        }
    }

    return $invokeResult
} catch { # Catch for the main try in Invoke-MSUpdate
    $CaughtOuterError = $_
    $invokeResult.ErrorOccurredInInvoke = $true
    # Redact any passwords from the error message before storing or logging
    $errorMessage = if ($CaughtOuterError.Exception.Message) {
        $CaughtOuterError.Exception.Message
    } else {
        "Unknown error occurred: $($CaughtOuterError.ToString())"
    }
    if ($errorMessage -match '://[^@]+@') {
        $errorMessage = $errorMessage -replace '(://)[^:]+:[^@]+@', '$1****:****@'
    }
    # Defensive split - handle null or empty messages
    $errorFirstLine = if ($errorMessage) {
        $errorMessage.Split([Environment]::NewLine)[0]
    } else {
        "Unknown error"
    }
    $invokeResult.StatusMessage = ("Error_InvokeMSUpdate_OuterTry: {0}" -f $errorFirstLine)
    Write-Log -Message ("Outer error in Invoke-MSUpdate for '{0}': {1}" -f $hostForPingInInvoke, $errorMessage) -Level ERROR
    # Errors are reported through ProgressReporter or return value, not direct toast updates

    # Return result even on error
    return $invokeResult
} finally {
    $ProgressPreference = $oldProgressPreference
    if ($callbackChanged) {
        Write-Log -Message "Restoring original SSL/TLS certificate validation callback in Invoke-MSUpdate." -Level DEBUG
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}
}