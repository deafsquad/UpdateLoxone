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
            # Path to the *directory* containing the installed LoxoneConfig.exe.
            [Parameter(Mandatory = $true)] [string]$InstalledExePath,
            # Path to the script's save folder (used for context).
            [Parameter(Mandatory = $true)] [string]$ScriptSaveFolder
        )

        Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber

        $anyMSUpdated = $false # Initialize flag

        try { # Main try block
            # --- Start of Logic ---
            $global:LogFile = $LogFile
            $script:DebugMode = $DebugMode.IsPresent
            Write-Log -Message "Starting Miniserver update check process..." -Level "INFO"

            if (-not (Test-Path $MSListPath)) {
                Write-Log -Message "Miniserver list file not found at '${MSListPath}'. Skipping Miniserver updates." -Level "WARN"
                return $false
            }

            $miniservers = Get-Content $MSListPath | Where-Object { $_ -match '\S' }
            Write-Log -Message "Loaded Miniserver list with $($miniservers.Count) entries." -Level "INFO"

            if ($miniservers.Count -eq 0) {
                Write-Log -Message "Miniserver list is empty. Skipping Miniserver updates." -Level "INFO"
                return $false
            }

            $loxoneConfigExe = Join-Path -Path $InstalledExePath -ChildPath "LoxoneConfig.exe"
            if (-not (Test-Path $loxoneConfigExe)) {
                Write-Log -Message "LoxoneConfig.exe not found (checked based on directory path '${InstalledExePath}'). Cannot perform Miniserver updates." -Level "ERROR"
                return $false
            }

            foreach ($msEntry in $miniservers) {
                $redactedEntryForLog = Get-RedactedPassword $msEntry # Corrected call
                Write-Log -Message "Processing Miniserver entry: ${redactedEntryForLog}" -Level INFO

                $msIP = $null
                $versionUri = $null
                $updateArg = $null
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
                    $uriBuilder.Port = 80
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
                            if ($_.Exception.Response -ne $null -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
                                Write-Log -Message "HTTPS check returned 503 (Updating). Assuming update needed/in progress." -Level WARN
                                $msVersionCheckSuccess = $true # Treat 503 as a reason to proceed to update/wait logic
                            } else {
                                Write-Log -Message "HTTPS failed (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream). Falling back to HTTP." -Level WARN
                            }
                        } catch {
                            Write-Log -Message "Unexpected error during HTTPS connection attempt: $($_.Exception.Message). Falling back to HTTP." -Level WARN
                        }
                    }

                    # Proceed with original protocol if HTTPS wasn't attempted or failed
                    if (-not $msVersionCheckSuccess) {
                        $originalParams = $iwrParamsBase.Clone() # Clone base params
                        $originalParams.Uri = $versionUri # Set original URI
                        $originalParams.ErrorAction = 'Stop' # Ensure ErrorAction is Stop
 
                        # Add AllowUnencryptedAuthentication directly if needed
                        if ($originalParams.ContainsKey('Credential')) {
                            $originalParams.AllowUnencryptedAuthentication = $true # RE-ADDED - Required by user's environment for HTTP+Credentials
                            Write-Log -Message "Attempting HTTP request to $msIP (with credentials, AllowUnencryptedAuthentication=$true)" -Level WARN
                        }
 
                        try {
                            $responseObject = Invoke-WebRequest @originalParams
                            Write-Log -Message "Connection successful using $($originalScheme.ToUpper()) URI: $versionUri" -Level INFO
                            $msVersionCheckSuccess = $true
                        } catch [System.Net.WebException] {
                            # Check for 503 specifically
                            if ($_.Exception.Response -ne $null -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
                                Write-Log -Message "$($originalScheme.ToUpper()) check returned 503 (Updating). Assuming update needed/in progress." -Level WARN
                                $msVersionCheckSuccess = $true # Treat 503 as a reason to proceed
                            }
                            # Check for the specific authentication error
                            elseif ($_.Exception.Message -like '*AllowUnencryptedAuthentication*') {
                                Write-Log -Message "Failed to connect using $($originalScheme.ToUpper()) URI: $($_.Exception.Message) Credentials blocked over HTTP." -Level ERROR
                                # $msVersionCheckSuccess remains false
                            }
                            # Log other WebExceptions
                            else {
                                Write-Log -Message "Failed to connect using $($originalScheme.ToUpper()) URI (WebException): $($_.Exception.Message). Status: $($_.Exception.Response.StatusCode | Out-String -Stream)" -Level WARN
                                # $msVersionCheckSuccess remains false
                            }
                        } catch {
                            # Log other general errors
                            Write-Log -Message "Unexpected error during $($originalScheme.ToUpper()) connection attempt: $($_.Exception.Message)" -Level ERROR
                            # $msVersionCheckSuccess remains false
                        }
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
                            Update-PersistentToast -NewStatus "Loxone AutoUpdate: Starting update for Miniserver ${msIP}..."

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
                                Credential = $credential # Pass credential object separately
                            }
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
                    Write-Log -Message "Continuing script execution after error processing Miniserver '$msIP'." -Level INFO # Added Log, Removed -ForceLog
                } # End outer try/catch for this MS
            } # End foreach loop
            Write-Log -Message "Finished processing all Miniservers." -Level "INFO"
            # --- End of Logic ---
        } # End main try block
        catch { # Main catch block
            Write-Log -Message "Unexpected error caught in main Update-MS try block: $($_.Exception.Message)" -Level ERROR
        } finally { # Main finally block
            Exit-Function # Corrected call
        }

        # Return the final status after try/catch/finally
        return $anyMSUpdated
    }

    function Invoke-MiniserverUpdate {
        param(
            # The full URI for the Miniserver, potentially including credentials (e.g., "http://user:pass@host").
            [Parameter(Mandatory=$true)][string]$MiniserverUri,
            # The target version string (normalized) for verification after update.
            [Parameter(Mandatory=$true)][string]$NormalizedDesiredVersion,
            # Optional PSCredential object for authenticating requests.
            [Parameter()][System.Management.Automation.PSCredential]$Credential = $null
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
 
        Write-Log -Message "Attempting to trigger update for Miniserver: ${redactedUri}" -Level INFO
 
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
                # Add AllowUnencryptedAuthentication ONLY if it's HTTP
                if ($scheme -eq 'http') {
                    $triggerParams.AllowUnencryptedAuthentication = $true # RE-ADDED - Required by user's environment for HTTP+Credentials
                    Write-Log -Message "Attempting HTTP update trigger to $hostForPing (with credentials, AllowUnencryptedAuthentication=$true)" -Level WARN
                }
            }
            Write-Log -Message "Triggering update via $autoupdateUri..." -Level DEBUG
            Invoke-WebRequest @triggerParams | Out-Null # Discard output, just need it to execute
            Write-Log -Message "Update trigger command sent to '${redactedUri}'." -Level INFO
            # --- End Trigger Update ---

            # --- Wait for Miniserver Reboot and Verify Update (Using HTTP Polling) ---
            Write-Log -Message "Waiting for Miniserver ${hostForPing} to become responsive after update trigger..." -Level INFO
            Update-PersistentToast -NewStatus "Waiting for Miniserver ${hostForPing} to reboot..."

            $startTime = Get-Date
            $timeout = New-TimeSpan -Minutes 15 # Total timeout for the Miniserver to come back and respond correctly
            $pollInterval = New-TimeSpan -Seconds 15 # How often to check the version endpoint
            $msResponsive = $false
            $lastResponse = $null
            $verificationSuccess = $false

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
                    $verifyParams.AllowUnencryptedAuthentication = $true
                }
            }

            while (((Get-Date) - $startTime) -lt $timeout) {
                try {
                    Write-Log -Message "Polling $verificationUri ..." -Level DEBUG
                    $lastResponse = Invoke-WebRequest @verifyParams # ErrorAction is Stop
                    
                    # If we get here, the request succeeded (likely 200 OK)
                    if ($lastResponse.StatusCode -eq 200) {
                        Write-Log -Message "Miniserver ${hostForPing} responded with 200 OK." -Level INFO
                        $msResponsive = $true
                        break # Exit the while loop
                    } else {
                        # Log unexpected success code, but continue polling
                        Write-Log -Message "Miniserver ${hostForPing} responded with unexpected status $($lastResponse.StatusCode). Continuing poll..." -Level WARN
                        Start-Sleep -Seconds $pollInterval.TotalSeconds
                    }
                } catch [System.Net.WebException] {
                    $statusCode = $null
                    if ($_.Exception.Response -ne $null) {
                        $statusCode = $_.Exception.Response.StatusCode
                    }

                    if ($statusCode -eq [System.Net.HttpStatusCode]::ServiceUnavailable) {
                        Write-Log -Message "Miniserver ${hostForPing} returned 503 (Updating/Rebooting)... Retrying in $($pollInterval.TotalSeconds)s." -Level DEBUG
                    } else {
                        Write-Log -Message "Miniserver ${hostForPing} WebException ($($statusCode)): $($_.Exception.Message). Retrying in $($pollInterval.TotalSeconds)s." -Level DEBUG
                    }
                    Start-Sleep -Seconds $pollInterval.TotalSeconds
                } catch {
                    # Catch other errors like connection refused, DNS errors, etc.
                    Write-Log -Message "Miniserver ${hostForPing} unreachable: $($_.Exception.Message). Retrying in $($pollInterval.TotalSeconds)s." -Level DEBUG
                    Start-Sleep -Seconds $pollInterval.TotalSeconds
                }
            } # End while loop

            # --- Verification after Polling ---
            if ($msResponsive -and $lastResponse) {
                Write-Log -Message "Miniserver ${hostForPing} is responsive. Verifying version..." -Level INFO
                Update-PersistentToast -NewStatus "Miniserver ${hostForPing} is responsive. Verifying version..."
                try {
                    $xmlAfterUpdate = [xml]$lastResponse.Content
                    $versionAfterUpdate = $xmlAfterUpdate.LL.value
                    if ([string]::IsNullOrEmpty($versionAfterUpdate)) {
                        throw "Could not find version value in Miniserver XML response after update."
                    }

                    $normalizedVersionAfterUpdate = Convert-VersionString $versionAfterUpdate

                    if ($normalizedVersionAfterUpdate) {
                        Write-Log -Message "Version after update: ${normalizedVersionAfterUpdate}" -Level INFO
                        if ($normalizedVersionAfterUpdate -eq $NormalizedDesiredVersion) {
                            Write-Log -Message "SUCCESS: Miniserver ${hostForPing} successfully updated and verified to version ${NormalizedDesiredVersion}." -Level INFO
                            Update-PersistentToast -NewStatus "SUCCESS: Miniserver ${hostForPing} updated to ${NormalizedDesiredVersion}."
                            $verificationSuccess = $true
                        } else {
                            Write-Log -Message "FAILURE: Miniserver ${hostForPing} update verification failed. Version after update (${normalizedVersionAfterUpdate}) does not match desired (${NormalizedDesiredVersion})." -Level ERROR
                            Update-PersistentToast -NewStatus "FAILED: Miniserver ${hostForPing} update verification failed. Found ${normalizedVersionAfterUpdate}, expected ${NormalizedDesiredVersion}."
                            $verificationSuccess = $false
                        }
                    } else {
                         Write-Log -Message "FAILURE: Could not determine a valid version for Miniserver ${hostForPing} after update attempt. Found raw value: '$versionAfterUpdate'." -Level ERROR
                         Update-PersistentToast -NewStatus "FAILED: Could not verify Miniserver ${hostForPing} version after update."
                         $verificationSuccess = $false
                    }
                } catch {
                    Write-Log -Message "FAILURE: Could not verify Miniserver ${hostForPing} version after update. Error during verification processing: $($_.Exception.Message)" -Level ERROR
                    Update-PersistentToast -NewStatus "FAILED: Could not verify Miniserver ${hostForPing} version after update (Error: $($_.Exception.Message))."
                    $verificationSuccess = $false
                }
            } else {
                # Loop timed out
                Write-Log -Message "FAILURE: Miniserver ${hostForPing} did not become responsive with a 200 OK status at $verificationUri within the timeout period ($($timeout.TotalMinutes) minutes)." -Level ERROR
                Update-PersistentToast -NewStatus "FAILED: Miniserver ${hostForPing} did not respond correctly after update attempt."
                $verificationSuccess = $false
            }
            
            return $verificationSuccess # Return true only if version verified successfully
            # --- End Wait and Verify (Using HTTP Polling) ---

        } catch {
            Write-Log -Message "Error triggering update for '${redactedUri}': $($_.Exception.Message)" -Level ERROR
            Update-PersistentToast -NewStatus "FAILED: Error triggering update for Miniserver ${hostForPing}: $($_.Exception.Message)."
            return $false # Indicate failure
        }
        } finally {
            Exit-Function
        }
    } # Closing brace for InvokeMiniserverUpdate
#endregion Miniserver Update Logic

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
Export-ModuleMember -Function Update-MS, Invoke-MiniserverUpdate
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.
# Removed leftover debug code that was outside function scope (lines 370-375)