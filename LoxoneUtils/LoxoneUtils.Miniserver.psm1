# Module for Loxone Update Script Miniserver Interaction Functions

#region Miniserver Update Logic
    function Update-MS {
        [CmdletBinding()]
        param(
            # The target Loxone Config version string (normalized).
            [Parameter(Mandatory = $true)] [string]$DesiredVersion,
            # Path to the text file containing Miniserver connection strings.
            [Parameter(Mandatory = $true)] [string]$MSListPath,
            # Path to the main log file.
            [Parameter(Mandatory = $true)] [string]$LogFile,
            # Maximum log file size in MB (passed for potential future use).
            [Parameter(Mandatory = $true)] [int]$MaxLogFileSizeMB,
            # Switch to enable debug logging.
            [Parameter()][switch]$DebugMode,
            # Path to the *directory* containing the installed LoxoneConfig.exe. # REMOVED - Not needed for URL-based update trigger
            # [Parameter(Mandatory = $true)] [string]$InstalledExePath, # REMOVED
            # Path to the script's save folder (used for context).
            [Parameter(Mandatory = $true)] [string]$ScriptSaveFolder,
            # Step info for toast updates
            [Parameter(Mandatory = $false)][int]$StepNumber = 1, # Default if not passed
            [Parameter(Mandatory = $false)][int]$TotalSteps = 1,  # Default if not passed
            # New switch to bypass SSL/TLS certificate validation
            [Parameter()][switch]$SkipCertificateCheck
        )

# Validate DesiredVersion parameter
        if ([string]::IsNullOrWhiteSpace($DesiredVersion)) {
            Write-Log -Message "Update-MS called with null or empty -DesiredVersion. Skipping update logic." -Level ERROR
            return $false # Cannot proceed without a target version
        }
        Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
        $script:ErrorOccurred = $false # Initialize error flag for this function scope

        $anyMSUpdated = $false # Initialize flag

        try { # Main try block
            # --- Start of Logic ---
            $global:LogFile = $LogFile
            $script:DebugMode = $DebugMode.IsPresent
            Write-Log -Message "Starting Miniserver update check process..." -Level "INFO"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            if (-not (Test-Path $MSListPath)) {
                Write-Log -Message "Miniserver list file not found at '${MSListPath}'. Skipping Miniserver updates." -Level "WARN"
                return $false
            }

            $miniservers = Get-Content $MSListPath | Where-Object { $_ -match '\S' }
            Write-Log -Message "Loaded Miniserver list with $($miniservers.Count) entries." -Level "INFO"

            if ($miniservers.Count -eq 0) {
                Write-Log -Message "Miniserver list is empty. Skipping Miniserver updates." -Level "INFO"
                return $true # No error, just no servers to update.
            }

            # Removed check for LoxoneConfig.exe (lines 49-53) as it's no longer needed for URL-based updates
            # and the associated parameter $InstalledExePath was removed.

            foreach ($msEntry in $miniservers) {
                $redactedEntryForLog = Get-RedactedPassword $msEntry # Corrected call
                Write-Log -Message "Processing Miniserver entry: ${redactedEntryForLog}" -Level INFO

                $msIP = $null
                $versionUri = $null
                $credential = $null

                try { # Inner try for parsing entry
                    $entryToParse = $msEntry
                    if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
                    $uriBuilder = [System.UriBuilder]$entryToParse
                    $msIP = $uriBuilder.Host

                    if (-not ([string]::IsNullOrWhiteSpace($uriBuilder.UserName))) {
                        $securePassword = $uriBuilder.Password | ConvertTo-SecureString -AsPlainText -Force
                        $credential = New-Object System.Management.Automation.PSCredential($uriBuilder.UserName, $securePassword)
                        $updateArg = $uriBuilder.UserName + ":" + $uriBuilder.Password + "@" + $uriBuilder.Host
                        Write-Log -Message "Parsed credentials for $msIP. User: $($uriBuilder.UserName)" -Level DEBUG
                    } else {
                        $updateArg = $msIP
                        Write-Log -Message "No credentials found for $msIP." -Level DEBUG
                    }

                    $uriBuilder.Path = "/dev/cfg/version"
                    # Port is handled implicitly by UriBuilder based on Scheme and original URI
                    $uriBuilder.Password = $null
                    $uriBuilder.UserName = $null
                    $versionUri = $uriBuilder.Uri.AbsoluteUri

                } catch { # Inner catch for parsing entry
                    Write-Log -Message "Failed to parse Miniserver entry '$redactedEntryForLog' as URI: $($_.Exception.Message). Assuming it's just an IP/hostname." -Level "WARN"
                    $credential = $null
                    $msIP = $msEntry.Split('@')[-1].Split('/')[0]
                    $updateArg = $msIP
                    if ($msIP) {
                        $versionUri = "http://${msIP}/dev/cfg/version"
                    } else {
                        Write-Log -Message "Could not determine IP/Host from entry '$redactedEntryForLog'. Skipping." -Level "ERROR"
                        continue # Skip to next entry in foreach
                    } # End of else block
                } # End inner catch for parsing entry <-- CORRECTED BRACE PLACEMENT

                $redactedVersionUri = Get-RedactedPassword $versionUri # Corrected call
                Write-Log -Message "Checking current Miniserver version for '$msIP' via URI: ${redactedVersionUri}" -Level "INFO"

                $responseObject = $null
                $msVersionCheckSuccess = $false
                $originalScheme = $null
                $iwrParamsBase = @{ TimeoutSec = 15; ErrorAction = 'Stop'; Method = 'Get' } # Base params without URI/Credential

                try { # Outer try for the whole version check + update process for this MS
                    $originalScheme = ([uri]$versionUri).Scheme # Get scheme reliably

                    # Add credential if present (applies to both HTTPS and HTTP attempts)
                    if ($credential) {
                        $iwrParamsBase.Credential = $credential
                        Write-Log -Message "Using credentials for Invoke-WebRequest to $msIP" -Level DEBUG
                    }

                    # --- Certificate Bypass Logic ---
                    $originalCallback = $null
                    $callbackChanged = $false
                    if ($SkipCertificateCheck.IsPresent) {
                        Write-Log -Message "WARNING: Bypassing Miniserver SSL/TLS certificate validation for $msIP due to -SkipCertificateCheck parameter." -Level WARN
                        $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                        $callbackChanged = $true
                    }
                    # --- End Certificate Bypass Logic ---
                    try { # Add outer try for callback restoration
                        if ($originalScheme -eq 'http') {
                            # Attempt HTTPS first
                            $httpsUriBuilder = [System.UriBuilder]$versionUri
                        $httpsUriBuilder.Scheme = 'https'
                        $httpsUriBuilder.Port = 443 # Standard HTTPS port
                        $httpsUri = $httpsUriBuilder.Uri.AbsoluteUri
                        $redactedHttpsUri = Get-RedactedPassword $httpsUri # Redact for logging
                        Write-Log -Message "Original URI is HTTP. Attempting secure connection first: $redactedHttpsUri" -Level INFO
                        $httpsParams = $iwrParamsBase.Clone() # Clone base params
                        $httpsParams.Uri = $httpsUri

                        try {
                            Write-Log -Message "Attempting Invoke-WebRequest with HTTPS..." -Level DEBUG
                            $responseObject = Invoke-WebRequest @httpsParams
                            Write-Log -Message "HTTPS connection successful." -Level INFO
                            $msVersionCheckSuccess = $true
                        } catch [System.Net.WebException] {
                            if ($null -ne $_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
                                Write-Log -Message "HTTPS check returned 503 (Updating). Assuming update needed/in progress." -Level WARN
                                $msVersionCheckSuccess = $true # Treat 503 as a reason to proceed to update/wait logic
                            } else {
                                Write-Log -Message "HTTPS failed (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream). Falling back to HTTP." -Level WARN
                                # Add more details in Debug mode
                                if ($Global:DebugPreference -eq 'Continue') {
                                    $exceptionDetails = "[Update-MS] HTTPS WebException Details for ${msIP}:"
                                    if ($_.Exception.Status) { $exceptionDetails += "`n  Status: $($_.Exception.Status)" }
                                    if ($_.Exception.Response) {
                                        try { # Handle potential errors reading response stream
                                            $responseStream = $_.Exception.Response.GetResponseStream()
                                            $streamReader = New-Object System.IO.StreamReader($responseStream)
                                            $responseBody = $streamReader.ReadToEnd()
                                            $streamReader.Close()
                                            $responseStream.Close()
                                            $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription)"
                                            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                                                $exceptionDetails += "`n  Response Body: $($responseBody)"
                                                }
                                        } catch {
                                            $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription) (Error reading response body: $($_.Exception.Message))"
                                        }
                                    }
                                    $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)"
                                    Write-Log -Message $exceptionDetails -Level DEBUG
                                }
                            }
                        } catch {
                            Write-Log -Message "Unexpected error during HTTPS connection attempt: $($_.Exception.Message). Falling back to HTTP." -Level WARN
                            # Add more details in Debug mode
                            if ($Global:DebugPreference -eq 'Continue') {
                                $exceptionDetails = "[Update-MS] HTTPS General Exception Details for ${msIP}:"
                                $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)"
                                Write-Log -Message $exceptionDetails -Level DEBUG
                            }
                        }
                    }

                    # Proceed with original protocol if HTTPS wasn't attempted or failed
                    if (-not $msVersionCheckSuccess) {
                        $originalParams = $iwrParamsBase.Clone() # Clone base params
                        $originalParams.Uri = $versionUri # Set original URI
                        $originalParams.ErrorAction = 'Stop' # Ensure ErrorAction is Stop
 
                        # Attempt HTTP connection
                        try {
                            # Modify hashtable directly and use standard splatting
                            if ($originalParams.ContainsKey('Credential')) {
                                Write-Log -Message "Attempting HTTP request to $msIP (with credentials)." -Level WARN
                                # Allow sending credentials over HTTP as fallback required by Miniserver configuration (Security Risk!)
                                $originalParams['-AllowUnencryptedAuthentication'] = $true # Add switch for HTTP+Credentials
                            } else {
                                Write-Log -Message "Attempting HTTP request to $msIP (without credentials)..." -Level DEBUG
                            }
                            $responseObject = Invoke-WebRequest @originalParams # Use standard splatting
                            Write-Log -Message "Connection successful using $($originalScheme.ToUpper()) URI: $versionUri" -Level INFO
                            $msVersionCheckSuccess = $true
                        } catch [System.Net.WebException] {
                            # Check for 503 specifically
                            if ($null -ne $_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
                                Write-Log -Message "$($originalScheme.ToUpper()) check returned 503 (Updating). Assuming update needed/in progress." -Level WARN
                                $msVersionCheckSuccess = $true # Treat 503 as a reason to proceed
                            }
                            # Log other WebExceptions
                            else {
                                Write-Log -Message "Failed to connect using $($originalScheme.ToUpper()) URI (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream)" -Level ERROR # Keep primary message as ERROR
                                # Add more details in Debug mode
                                if ($Global:DebugPreference -eq 'Continue') {
                                    $exceptionDetails = "[Update-MS] HTTP WebException Details for ${msIP}:"
                                    if ($_.Exception.Status) { $exceptionDetails += "`n  Status: $($_.Exception.Status)" }
                                    if ($_.Exception.Response) {
                                        try { # Handle potential errors reading response stream
                                            $responseStream = $_.Exception.Response.GetResponseStream()
                                            $streamReader = New-Object System.IO.StreamReader($responseStream)
                                            $responseBody = $streamReader.ReadToEnd()
                                            $streamReader.Close()
                                            $responseStream.Close()
                                            $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription)"
                                            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                                                $exceptionDetails += "`n  Response Body: $($responseBody)"
                                            }
                                        } catch {
                                            $exceptionDetails += "`n  Response: $($_.Exception.Response.StatusCode) / $($_.Exception.Response.StatusDescription) (Error reading response body: $($_.Exception.Message))"
                                        }
                                    }
                                    $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)"
                                    Write-Log -Message $exceptionDetails -Level DEBUG # Log extra details at DEBUG level
                                }
                                $script:ErrorOccurred = $true # Ensure error flag is set
                                # $msVersionCheckSuccess remains false
                            }
                        } catch {
                            # Log other general errors
                            Write-Log -Message "Unexpected error during $($originalScheme.ToUpper()) connection attempt: $($_.Exception.Message)" -Level ERROR # Keep primary message as ERROR
                            # Add more details in Debug mode
                            if ($Global:DebugPreference -eq 'Continue') {
                                $exceptionDetails = "[Update-MS] HTTP General Exception Details for ${msIP}:"
                                $exceptionDetails += "`n  Full Exception: $($_.Exception | Out-String)"
                                Write-Log -Message $exceptionDetails -Level DEBUG # Log extra details at DEBUG level
                            }
                            $script:ErrorOccurred = $true # Ensure error flag is set
                            # $msVersionCheckSuccess remains false
                        }
                    } # End HTTP connection try/catch
                } finally { # Finally for the try block started on line 125 (wrapping connection attempts)
                    # --- Restore Certificate Callback ---
                    if ($callbackChanged) {
                        Write-Log -Message "Restoring original SSL/TLS certificate validation callback for $msIP." -Level DEBUG
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
                    }
                    # --- End Restore Certificate Callback ---
                }

                    # --- Process response ONLY if a connection succeeded ---
                    if ($msVersionCheckSuccess -and $responseObject) {
                        if ($DebugMode) {
                            $rawResponseContent = $responseObject.RawContent
                            $debugMsg = "DEBUG: Raw response content from $($msIP): $rawResponseContent"
                            Write-Log -Message $debugMsg -Level DEBUG
                        }

                        $xmlResponse = [xml]$responseObject.Content
                        $currentVersion = $xmlResponse.LL.value
                        if ($null -eq $xmlResponse -or $null -eq $xmlResponse.LL -or $null -eq $xmlResponse.LL.value) { throw "Could not find version value in parsed Miniserver response XML (Expected structure: LL.value)." }

                        Write-Log -Message "Miniserver '$msIP' current version: ${currentVersion}" -Level "INFO"
                        $normalizedCurrentVersion = Convert-VersionString $currentVersion

                        Write-Log -Message "Comparing current version (${normalizedCurrentVersion}) with desired version (${DesiredVersion})." -Level DEBUG
                        if ($normalizedCurrentVersion -ne $DesiredVersion) {
                            Write-Log -Message "Update required for Miniserver at '$msIP' (Current: ${normalizedCurrentVersion}, Desired: ${DesiredVersion}). Triggering update..." -Level "INFO"
                            # Update toast using correct parameters
                            $toastParamsMSStart = @{ StepNumber = $StepNumber; TotalSteps = $TotalSteps; StepName = "Starting update for MS ${msIP}..." }
                            Update-PersistentToast @toastParamsMSStart
    
                            # Construct the full URI including credentials if they exist
                            $uriForUpdate = $versionUri # Start with the base version URI (http://host/dev/cfg/version)
                            if ($credential) {
                                $uriBuilderForUpdate = [System.UriBuilder]$versionUri
                                $uriBuilderForUpdate.UserName = $credential.UserName
                                $uriBuilderForUpdate.Password = $credential.GetNetworkCredential().Password
                                $uriForUpdate = $uriBuilderForUpdate.Uri.AbsoluteUri
                            }
 
                            $invokeParams = @{
                                MiniserverUri = $uriForUpdate # Pass the full URI
                                NormalizedDesiredVersion = $DesiredVersion
                                Credential = $credential # Pass credential object separately (Removed comma)
                                # Pass step info down
                                StepNumber = $StepNumber
                                TotalSteps = $TotalSteps
                            } # Corrected closing brace placement
                            $updateSuccess = Invoke-MiniserverUpdate @invokeParams
                            if ($updateSuccess) {
                                $anyMSUpdated = $true
                                Write-Log -Message "Update successful for Miniserver '$msIP'." -Level INFO
                            } else {
                                Write-Log -Message "Update attempt failed or verification failed for Miniserver '$msIP'." -Level WARN
                            }
                        } else {
                            Write-Log -Message "Miniserver at '$msIP' is already up-to-date (Version: ${normalizedCurrentVersion}). Skipping update." -Level "INFO"
                        }

                    } elseif (-not $msVersionCheckSuccess) {
                        Write-Log -Message "Failed to check Miniserver version for '$msIP' (URI: ${redactedVersionUri}) after attempting relevant protocols. Skipping." -Level "ERROR"
                    } # End of if/elseif for successful connection check
                } catch { # Outer catch for the whole MS processing
                    Write-Log -Message "Caught exception during processing for Miniserver '$msIP'. Error: $($_.Exception.Message)" -Level ERROR # Existing log, Removed -ForceLog
                    $script:ErrorOccurred = $true # Set the main script error flag
                    Write-Log -Message "Continuing script execution after error processing Miniserver '$msIP'." -Level INFO # Added Log, Removed -ForceLog
                } # End outer try/catch for this MS
            } # End foreach loop
            Write-Log -Message "Finished processing all Miniservers." -Level "INFO"
            # --- End of Logic ---
        } # End main try block
        catch { # Main catch block
            Write-Log -Message "Unexpected error caught in main Update-MS try block: $($_.Exception.Message)" -Level ERROR
            $script:ErrorOccurred = $true # Set the main script error flag
        } finally { # Main finally block
            Exit-Function # Corrected call
        }

        # Return the final status after try/catch/finally
        # Final return logic: Return $false if any error occurred, otherwise return whether any MS was updated.
        if ($script:ErrorOccurred) {
            Write-Log -Message "Update-MS returning `$false due to errors encountered during processing." -Level WARN
            return $false
        } else {
            Write-Log -Message "Update-MS returning `$anyMSUpdated: $anyMSUpdated (No errors encountered)." -Level INFO
            return $anyMSUpdated
        }
    }

    function Invoke-MiniserverUpdate {
        param(
            # The full URI for the Miniserver, potentially including credentials (e.g., "http://user:pass@host").
            [Parameter(Mandatory=$true)][string]$MiniserverUri,
            # The target version string (normalized) for verification after update.
            [Parameter(Mandatory=$true)][string]$NormalizedDesiredVersion,
            # Optional PSCredential object for authenticating requests.
            [Parameter()][System.Management.Automation.PSCredential]$Credential = $null,
            # Step info for toast updates
            [Parameter(Mandatory = $false)][int]$StepNumber = 1, # Default if not passed
            [Parameter(Mandatory = $false)][int]$TotalSteps = 1  # Default if not passed
        )
        Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
        try {
        # Derive values needed for logging, pinging, and requests from MiniserverUri
        $redactedUri = Get-RedactedPassword $MiniserverUri
        $uriObject = [System.Uri]$MiniserverUri # Parse once
        $hostForPing = $uriObject.Host
        $scheme = $uriObject.Scheme
        $verificationUri = "$($scheme)://$($uriObject.Authority)/dev/cfg/version" # Construct version URI
        $autoupdateUri = "$($scheme)://$($uriObject.Authority)/dev/sys/autoupdate" # Construct autoupdate URI
 
        $redactedAutoupdateUri = Get-RedactedPassword $autoupdateUri # Redact the correct URI for logging
        Write-Log -Message "Attempting to trigger update for Miniserver via: ${redactedAutoupdateUri}" -Level INFO # Use redacted autoupdate URI in log

        try {
            # --- Trigger Update via URL ---
            $triggerParams = @{
                Uri = $autoupdateUri
                Method = 'Get' # Typically a GET request triggers it
                TimeoutSec = 30 # Shorter timeout for trigger
                ErrorAction = 'Stop'
            }
            if ($Credential) {
                $triggerParams.Credential = $Credential
                # Add -AllowUnencryptedAuthentication switch parameter ONLY if it's HTTP
                if ($scheme -eq 'http') {
                    $triggerParams['-AllowUnencryptedAuthentication'] = $true # Correct way to add a switch parameter
                    Write-Log -Message "Attempting HTTP update trigger to $hostForPing (with credentials, using -AllowUnencryptedAuthentication)" -Level WARN
                }
            }
            Write-Log -Message "Triggering update via $autoupdateUri..." -Level DEBUG
            Invoke-WebRequest @triggerParams | Out-Null # Discard output, just need it to execute
            Write-Log -Message "Update trigger command sent to '${redactedUri}'." -Level INFO
            # --- End Trigger Update ---

            # --- Wait for Miniserver Reboot and Verify Update (Using HTTP Polling) ---
            Write-Log -Message "Waiting for Miniserver ${hostForPing} to become responsive after update trigger..." -Level INFO
            $toastParamsMSReboot = @{ StepNumber = $StepNumber; TotalSteps = $TotalSteps; StepName = "Waiting for MS ${hostForPing} to reboot..." }
            Update-PersistentToast @toastParamsMSReboot

            $startTime = Get-Date
            $timeout = New-TimeSpan -Minutes 15 # Total timeout for the Miniserver to come back and respond correctly
            $pollInterval = New-TimeSpan -Seconds 15 # How often to check the version endpoint
            $msResponsive = $false
            $lastResponse = $null
            $verificationSuccess = $false
            $loggedUpdatingStatus = $false # Flag to ensure 503 'Updating' status is logged only once

            # Prepare verification parameters (used inside loop)
            $verifyParams = @{
                Uri = $verificationUri
                UseBasicParsing = $true # Often needed for simple XML responses
                TimeoutSec = 10 # Shorter timeout for individual poll attempts
                ErrorAction = 'Stop' # Set to Stop for try/catch handling inside loop
            }
            if ($Credential) {
                $verifyParams.Credential = $Credential
                if ($scheme -eq 'http') {
                    $verifyParams['-AllowUnencryptedAuthentication'] = $true # Correct way to add a switch parameter
                }
            }

            $Attempts = 0
            $MaxAttempts = [Math]::Floor($timeout.TotalSeconds / 10) # Based on 10s sleep
            $LastPollStatusMessage = "Initiating..."

            while (((Get-Date) - $startTime) -lt $timeout) {
                $Attempts++
                # Display progress on a single line
                Write-Host -NoNewline ("`rPolling Miniserver $hostForPing (Attempt $Attempts/$MaxAttempts): $LastPollStatusMessage".PadRight(120)) # Pad to clear previous line

                # Wait 10 seconds between checks
                Start-Sleep -Seconds 10

                try {
                    Write-Log -Message "Polling $verificationUri (Attempt $Attempts/$MaxAttempts)..." -Level DEBUG # Added attempt info to log
                    # Dynamically build and execute the command for polling
                    # Modify hashtable directly and use standard splatting for polling
                    $pollHeaders = @{} # Initialize headers for polling
                    # Check if Credential exists AND scheme is http before adding Authorization header
                    if ($verifyParams.ContainsKey('Credential') -and $scheme -eq 'http') {
                        Write-Log -Message "Polling HTTP $hostForPing (with credentials, using Authorization header)." -Level WARN
                        $pollCredentialObject = $verifyParams.Credential
                        $pollUserName = $pollCredentialObject.UserName
                        $pollPassword = $pollCredentialObject.GetNetworkCredential().Password
                        $pollEncodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${pollUserName}:${pollPassword}"))
                        $pollHeaders.Authorization = "Basic $pollEncodedCredentials"
                        # Remove Credential from splatting params as we're using header auth
                        $verifyParams.Remove('Credential')
                    }
                    $lastResponse = Invoke-WebRequest @verifyParams -Headers $pollHeaders # Use standard splatting + Headers
                    # If we get here, the request succeeded (status code check)
                    if ($lastResponse.StatusCode -eq 200) {
                        Write-Log -Message "Miniserver ${hostForPing} responded with 200 OK. Checking version..." -Level INFO
                        $msResponsive = $true # Mark as responsive
                        # Now check the version from this successful response
                        try {
                            $xmlCurrent = [xml]$lastResponse.Content
                            $versionCurrent = $xmlCurrent.LL.value
                            if ([string]::IsNullOrEmpty($versionCurrent)) { throw "Could not find version value in current poll response." }
                            $normalizedVersionCurrent = Convert-VersionString $versionCurrent

                            if ($normalizedVersionCurrent -eq $NormalizedDesiredVersion) {
                                Write-Log -Message "Version matches desired version ($NormalizedDesiredVersion). Update successful." -Level INFO
                                $verificationSuccess = $true # Set success flag
                                $LastPollStatusMessage = "OK - Version $NormalizedDesiredVersion" # Update status before break
                                break # Exit the while loop - SUCCESS
                            } else {
                                Write-Log -Message "Miniserver ${hostForPing} responded with 200 OK, but version is still '$normalizedVersionCurrent' (Expected '$NormalizedDesiredVersion'). Continuing poll..." -Level DEBUG
                                $LastPollStatusMessage = "OK - Version $normalizedVersionCurrent (Expected $NormalizedDesiredVersion)" # Update status
                                # Do not break, continue polling after sleep
                                } # End of if/else for version check
                            } catch { # Catch block for version parsing try (line 449)
                                Write-Log -Message "Error parsing version from 200 OK response: $($_.Exception.Message). Continuing poll..." -Level WARN
                                $LastPollStatusMessage = "OK - Error parsing version: $($_.Exception.Message.Split([Environment]::NewLine)[0])" # Update status
                                # Do not break, continue polling after sleep
                            }
                        } else { # Handle non-200 success codes (line 445)
                            Write-Log -Message "Miniserver ${hostForPing} responded with unexpected status $($lastResponse.StatusCode). Continuing poll..." -Level WARN
                            $LastPollStatusMessage = "Responded with $($lastResponse.StatusCode)" # Update status
                            # Start-Sleep -Seconds $pollInterval.TotalSeconds # Sleep is at the start of the loop now
                        }
                    } catch [System.Net.WebException] { # Catch block for polling Invoke-WebRequest (line 443)
                        $statusCode = $null
                        $errorDetail = $null # Initialize errorDetail

                        if ($null -ne $_.Exception.Response) {
                            $statusCode = [int]$_.Exception.Response.StatusCode # Cast to int

                            if ($statusCode -eq 503) {
                                try {
                                    # Read the response body to check for specific error detail
                                    $responseStream = $_.Exception.Response.GetResponseStream()
                                    $streamReader = New-Object System.IO.StreamReader($responseStream)
                                    $responseBody = $streamReader.ReadToEnd()
                                    $streamReader.Close()
                                    $responseStream.Close()

                                    # Extract error detail using regex
                                    if ($responseBody -match '<errordetail>(.*?)</errordetail>') {
                                        $errorDetail = $matches[1].Trim() # Trim whitespace
                                    } else {
                                        $errorDetail = 'Updating (detail unavailable)'
                                    }
                                    $LastPollStatusMessage = "Updating ($errorDetail)" # Update status

                                    # Log the specific updating status ONCE
                                    if (-not $loggedUpdatingStatus) {
                                        Write-Log -Level INFO -Message "Miniserver $hostForPing status: $errorDetail"
                                        $loggedUpdatingStatus = $true # Set flag so it doesn't log again
                                    } else {
                                        # Log subsequent 503s only at DEBUG level to avoid spamming INFO logs
                                        Write-Log -Message "Miniserver ${hostForPing} still reporting 503 ($errorDetail)..." -Level DEBUG
                                    }
                                } catch {
                                    # If reading the response body fails, log generic 503
                                    Write-Log -Message "Miniserver ${hostForPing} returned 503 (Updating/Rebooting - Error reading detail: $($_.Exception.Message))..." -Level DEBUG
                                    $LastPollStatusMessage = "Updating (503 - Error reading detail)" # Update status
                                }
                            } else {
                                # Log other WebExceptions
                                Write-Log -Message "Miniserver ${hostForPing} WebException ($($statusCode)): $($_.Exception.Message). Retrying..." -Level WARN
                                $LastPollStatusMessage = "Error ($($statusCode)): $($_.Exception.Message.Split([Environment]::NewLine)[0])" # Update status (first line only)
                            }
                        } else {
                            # Handle cases where there's no response object (e.g., connection timeout)
                             Write-Log -Message "Miniserver ${hostForPing} WebException (No Response): $($_.Exception.Message). Retrying..." -Level WARN
                             $LastPollStatusMessage = "Error (No Response): $($_.Exception.Message.Split([Environment]::NewLine)[0])" # Update status (first line only)
                        }
                        # No sleep needed here, it happens at the start of the next loop iteration.
                    } catch { # Catch block for other polling errors (line 523)
                        # Catch other errors like connection refused, DNS errors, etc.
                        Write-Log -Message "Miniserver ${hostForPing} unreachable: $($_.Exception.Message). Retrying..." -Level WARN
                        $LastPollStatusMessage = "Unreachable: $($_.Exception.Message.Split([Environment]::NewLine)[0])" # Update status (first line only)
                        # No sleep needed here, it happens at the start of the next loop iteration.
                    }
                } # End while loop (line 419)

                # --- Final Status Check After Loop ---
                Write-Host "" # Add a newline to move off the progress line
                # This block now executes only if the loop finished (either by break or timeout)
                if ($verificationSuccess) {
                    # Success was already determined and logged within the loop
                    Write-Log -Message "Verification successful for Miniserver ${hostForPing} (Version: $NormalizedDesiredVersion)." -Level INFO
                    # Toast was already updated on success within the loop
                } elseif ($msResponsive) {
                    # Loop finished, MS was responsive at some point, but version never matched (or couldn't be parsed)
                    Write-Log -Message "FAILURE: Miniserver ${hostForPing} became responsive, but version verification failed within the timeout period. Final checked version might be old or unparsable." -Level ERROR
                    $toastParamsMSFailVerifyLoop = @{ StepNumber = $StepNumber; TotalSteps = $TotalSteps; StepName = "FAILED: MS ${hostForPing} verification failed (Timeout/Version Mismatch)." }
                    Update-PersistentToast @toastParamsMSFailVerifyLoop
                    $verificationSuccess = $false # Ensure it's false
                } else {
                    # Loop timed out without the Miniserver ever becoming responsive with 200 OK
                    Write-Log -Message "FAILURE: Miniserver ${hostForPing} did not become responsive with a 200 OK status at $verificationUri within the timeout period ($($timeout.TotalMinutes) minutes)." -Level ERROR
                    $toastParamsMSFailTimeout = @{ StepNumber = $StepNumber; TotalSteps = $TotalSteps; StepName = "FAILED: MS ${hostForPing} did not respond after update." }
                    Update-PersistentToast @toastParamsMSFailTimeout
                    $verificationSuccess = $false # Ensure it's false
                }

            } catch { # Catch for the inner try block (line 360) handling Trigger + Wait/Verify logic
                # Log error from the update/verify process
                Write-Log -Message "Error during update trigger or verification for '${redactedUri}': $($_.Exception.Message)" -Level ERROR
                $script:ErrorOccurred = $true # Set the main script error flag
                $toastParamsMSFailInner = @{ StepNumber = $StepNumber; TotalSteps = $TotalSteps; StepName = "FAILED: Error during update/verify for MS ${hostForPing}: $($_.Exception.Message)." }
                Update-PersistentToast @toastParamsMSFailInner
                $verificationSuccess = $false # Ensure failure
            } # End catch for inner try block (line 360)
        } finally { # Finally for the outer try block (line 359)
            # --- Restore Certificate Callback ---
            if ($callbackChanged) {
                Write-Log -Message "Restoring original SSL/TLS certificate validation callback for ${hostForPing} in Invoke-MiniserverUpdate." -Level DEBUG
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
            }
            # --- End Restore Certificate Callback ---
        }
        # Return statement should be outside the finally block but inside the function scope
        return $verificationSuccess
    } # Closing brace for Invoke-MiniserverUpdate
#endregion Miniserver Update Logic

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
Export-ModuleMember -Function Update-MS, Invoke-MiniserverUpdate
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.
# Removed leftover debug code that was outside function scope (lines 370-375)