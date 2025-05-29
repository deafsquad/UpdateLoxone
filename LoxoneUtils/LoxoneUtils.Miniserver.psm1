# Module for Loxone Update Script MS Interaction Functions

#region MS Update Logic

function Get-MiniserverVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MSEntry,

        [Parameter()]
        [switch]$SkipCertificateCheck,

        [Parameter()]
        [int]$TimeoutSec = 15 # Default timeout
    ) # Closing paren for param block
# Entry and Parameters Logging
$FunctionName = $MyInvocation.MyCommand.Name
Enter-Function -FunctionName $FunctionName -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
Write-Log -Level DEBUG -Message "Entering function '$($FunctionName)'."
Write-Log -Level DEBUG -Message "Parameters for '$($FunctionName)':"
Write-Log -Level DEBUG -Message ("  MSEntry (original): '{0}'" -f ($MSEntry -replace "([Pp]assword=)[^;]+", '$1********'))
Write-Log -Level DEBUG -Message ("  SkipCertificateCheck: {0}" -f $SkipCertificateCheck.IsPresent)
Write-Log -Level DEBUG -Message ("  TimeoutSec: {0}" -f $TimeoutSec)
# Credentials will be logged if used, after parsing.

$result = [PSCustomObject]@{
    MSIP       = "Unknown"
    RawVersion = $null
    Version    = $null # Initialize Version property
    Error      = $null
}

    $msIP = $null; $versionUri = $null; $credential = $null
    $originalCallback = $null; $callbackChanged = $false
    $oldProgressPreference = $ProgressPreference

    try {
        $ProgressPreference = 'SilentlyContinue' # Suppress progress for this internal function

        $entryToParse = $MSEntry
        if ($entryToParse -notmatch '^[a-zA-Z]+://') { $entryToParse = "http://" + $entryToParse }
        $uriBuilder = [System.UriBuilder]$entryToParse
        $result.MSIP = $uriBuilder.Host
        $msIP = $result.MSIP # For logging consistency if needed later

        if (-not ([string]::IsNullOrWhiteSpace($uriBuilder.UserName))) {
            $securePassword = $uriBuilder.Password | ConvertTo-SecureString -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($uriBuilder.UserName, $securePassword)
            Write-Log -Level DEBUG -Message ("$($FunctionName): Parsed UriBuilder.UserName: '{0}'" -f $uriBuilder.UserName)
            Write-Log -Level DEBUG -Message ("$($FunctionName): Parsed UriBuilder.Password: (length {0})" -f $uriBuilder.Password.Length) # Log length for security
            Write-Log -Level DEBUG -Message ("$($FunctionName): Credential object created for user: '{0}'" -f $credential.UserName)
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): UriBuilder.UserName is NULL or Whitespace. No credential object created from URI.")
        }

        $uriBuilder.Path = "/dev/cfg/version"
        $uriBuilder.Password = $null; $uriBuilder.UserName = $null # Clear credentials from URI for version check
        $versionUri = $uriBuilder.Uri.AbsoluteUri

        Write-Log -Message ("$($FunctionName): Checking MS version for '{0}' (derived from MSEntry)." -f $msIP) -Level DEBUG
        Write-Log -Level DEBUG -Message ("$($FunctionName): Base URI for version check (before potential HTTPS/HTTP switch): {0}" -f $versionUri) # Log Base URI
        if ($credential) {
            Write-Log -Level DEBUG -Message ("$($FunctionName): Using credential for user: '{0}'" -f $credential.UserName)
        } else {
            Write-Log -Level DEBUG -Message ("$($FunctionName): No credentials parsed from MSEntry.")
        }

        if ($SkipCertificateCheck.IsPresent) {
            $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $callbackChanged = $true
            Write-Log -Message ("Get-MiniserverVersion: SSL certificate check temporarily disabled for {0}." -f $msIP) -Level DEBUG
        }

        $responseObject = $null
        $iwrParams = @{ Uri = $versionUri; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop'; Method = 'Get' } # Use explicit 'Stop' to catch here
        if ($credential) { $iwrParams.Credential = $credential }

        try { # Main try for Invoke-WebRequest logic
            if ($uriBuilder.Scheme -eq 'http') {
                $httpsUriBuilder = [System.UriBuilder]$versionUri
                $httpsUriBuilder = [System.UriBuilder]$versionUri
                $httpsUriBuilder.Scheme = 'https'; $httpsUriBuilder.Port = 443 # Default HTTPS port
                try { # Try HTTPS first
                    $iwrParams.Uri = $httpsUriBuilder.Uri.AbsoluteUri
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Attempting HTTPS connection. Exact URI for Invoke-WebRequest: {0}" -f $iwrParams.Uri)
                    if ($PSVersionTable.PSVersion.Major -ge 6) { # SslProtocol available in PS 6+
                        $responseObject = Invoke-WebRequest @iwrParams -SslProtocol Tls12
                    } else {
                        $responseObject = Invoke-WebRequest @iwrParams
                    }
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS Invoke-WebRequest successful. StatusCode: {0}" -f $responseObject.StatusCode)
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS Content Snippet (first 100 chars): '{0}'" -f ($responseObject.Content | Select-String -Pattern '^.{0,100}' | ForEach-Object {$_.Matches[0].Value}))
                } catch { # Catch for HTTPS attempt
                    $CaughtHttpsError = $_
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS connection to '{0}' failed. Full Exception: {1}" -f $httpsUriBuilder.Uri.AbsoluteUri, $CaughtHttpsError.Exception.ToString())
                    if ($CaughtHttpsError.Exception -is [System.Net.WebException] -and $null -ne $CaughtHttpsError.Exception.Response) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): HTTPS WebException Status: {0}, Description: {1}" -f $CaughtHttpsError.Exception.Response.StatusCode, $CaughtHttpsError.Exception.Response.StatusDescription)
                    }
                    Write-Log -Message ("$($FunctionName): HTTPS connection to '{0}' failed ('{1}'). Falling back to HTTP." -f $msIP, $CaughtHttpsError.Exception.Message.Split([Environment]::NewLine)[0]) -Level DEBUG
                    
                    # Fallback to HTTP
                    $iwrParams.Uri = $versionUri # Revert to original HTTP URI
                    if ($credential -and $PSVersionTable.PSVersion.Major -ge 6) {
                        $iwrParams.AllowUnencryptedAuthentication = $true
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Added AllowUnencryptedAuthentication for HTTP fallback (PSVersion >= 6).")
                    } elseif ($credential) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Credential present for HTTP fallback (PSVersion < 6). AllowUnencryptedAuthentication not applicable/added by default by IWR for -Credential on HTTP.")
                    }
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Attempting HTTP connection (fallback). Exact URI for Invoke-WebRequest: {0}" -f $iwrParams.Uri)
                    Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Fallback iwrParams: $($iwrParams | Out-String)")
                    try {
                        $responseObject = Invoke-WebRequest @iwrParams # This will throw to the outer catch if it fails
                        Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Invoke-WebRequest successful (fallback). StatusCode: {0}" -f $responseObject.StatusCode)
                        Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP Content Snippet (fallback) (first 100 chars): '{0}'" -f ($responseObject.Content | Select-String -Pattern '^.{0,100}' | ForEach-Object {$_.Matches[0].Value}))
                    } catch {
                        $CaughtHttpFallbackError = $_
                        Write-Log -Level WARN -Message ("$($FunctionName): HTTP connection (fallback) to '{0}' also failed. Full Exception: {1}" -f $iwrParams.Uri, $CaughtHttpFallbackError.Exception.ToString())
                        if ($CaughtHttpFallbackError.Exception -is [System.Net.WebException] -and $null -ne $CaughtHttpFallbackError.Exception.Response) {
                            Write-Log -Level DEBUG -Message ("$($FunctionName): HTTP (fallback) WebException Status: {0}, Description: {1}" -f $CaughtHttpFallbackError.Exception.Response.StatusCode, $CaughtHttpFallbackError.Exception.Response.StatusDescription)
                        }
                        throw $CaughtHttpFallbackError # Re-throw to be caught by the main IWR logic catch
                    }
                }
            } else { # HTTPS was originally specified
                Write-Log -Level DEBUG -Message ("$($FunctionName): Attempting original HTTPS connection. Exact URI for Invoke-WebRequest: {0}" -f $iwrParams.Uri)
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        $iwrParamsSsl = $iwrParams | Add-Member -MemberType NoteProperty -Name SslProtocol -Value Tls12 -PassThru -Force
                        $responseObject = Invoke-WebRequest @iwrParamsSsl
                    } else {
                        $responseObject = Invoke-WebRequest @iwrParams
                    }
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Original HTTPS Invoke-WebRequest successful. StatusCode: {0}" -f $responseObject.StatusCode)
                    Write-Log -Level DEBUG -Message ("$($FunctionName): Original HTTPS Content Snippet (first 100 chars): '{0}'" -f ($responseObject.Content | Select-String -Pattern '^.{0,100}' | ForEach-Object {$_.Matches[0].Value}))
                } catch {
                    $CaughtOriginalHttpsError = $_
                    Write-Log -Level WARN -Message ("$($FunctionName): Original HTTPS connection to '{0}' failed. Full Exception: {1}" -f $iwrParams.Uri, $CaughtOriginalHttpsError.Exception.ToString())
                    if ($CaughtOriginalHttpsError.Exception -is [System.Net.WebException] -and $null -ne $CaughtOriginalHttpsError.Exception.Response) {
                        Write-Log -Level DEBUG -Message ("$($FunctionName): Original HTTPS WebException Status: {0}, Description: {1}" -f $CaughtOriginalHttpsError.Exception.Response.StatusCode, $CaughtOriginalHttpsError.Exception.Response.StatusDescription)
                    }
                    throw $CaughtOriginalHttpsError # Re-throw to be caught by the main IWR logic catch
                }
            }

            # Process response if any was successful
            if ($responseObject) {
                $xmlResponse = [xml]$responseObject.Content
                $result.RawVersion = $xmlResponse.LL.value
                if ([string]::IsNullOrEmpty($result.RawVersion)) {
                    Write-Log -Level WARN -Message ("$($FunctionName): Could not parse version from MS '{0}' (LL.value empty in response: '$($responseObject.Content | Select-String -Pattern '^.{0,200}' | ForEach-Object {$_.Matches[0].Value})')." -f $msIP)
                    throw ("Could not parse version from MS '{0}' (LL.value empty)." -f $msIP)
                }
                $result.Version = Convert-VersionString $result.RawVersion # Assuming Convert-VersionString is available
                Write-Log -Level DEBUG -Message ("$($FunctionName): Extracted Version: '{0}', RawVersion from XML: '{1}' for MS: '{2}'" -f $result.Version, $result.RawVersion, $msIP)
            } else {
                # This case should ideally not be reached if ErrorAction='Stop' is effective for all IWR calls.
                Write-Log -Level WARN -Message ("$($FunctionName): Failed to get a valid response object for version check of MS '{0}' after all attempts." -f $msIP)
                throw ("Failed to get a valid response for version check of MS '{0}' after all attempts." -f $msIP)
            }
        } catch { # Catch for the main Invoke-WebRequest logic try block (catches re-thrown errors from inner blocks too)
            $CaughtIwrError = $_
            $result.Error = ("Error during Invoke-WebRequest for '{0}': {1}" -f $msIP, $CaughtIwrError.Exception.Message.Split([Environment]::NewLine)[0])
            Write-Log -Level WARN -Message $result.Error
            Write-Log -Level DEBUG -Message ("$($FunctionName): Full Invoke-WebRequest error details for MS '{0}': {1}" -f $msIP, $CaughtIwrError.Exception.ToString())
            if ($CaughtIwrError.Exception -is [System.Net.WebException] -and $null -ne $CaughtIwrError.Exception.Response) {
                 Write-Log -Level DEBUG -Message ("$($FunctionName): WebException Details - Status: {0}, Description: {1}" -f $CaughtIwrError.Exception.Response.StatusCode, $CaughtIwrError.Exception.Response.StatusDescription)
            }
        }
    } catch { # This is the CATCH for the OUTER try block (started line 39)
        $OuterCaughtError = $_
        $result.Error = ("Outer error in Get-MiniserverVersion for '{0}': {1}" -f $msIP, $OuterCaughtError.Exception.Message.Split([Environment]::NewLine)[0])
        Write-Log -Level WARN -Message $result.Error # Log the general outer error
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
}
function Update-MS {
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$DesiredVersion,
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
                    $iwrParamsInitialCheck = @{ Uri = $versionUriForCheck; TimeoutSec = 15; ErrorAction = 'Stop'; Method = 'Get' }
                    if ($credential) { $iwrParamsInitialCheck.Credential = $credential }
    
                    if ($uriBuilder.Scheme -eq 'http') {
                        $httpsUriBuilderCheck = [System.UriBuilder]$versionUriForCheck
                        $httpsUriBuilderCheck.Scheme = 'https'; $httpsUriBuilderCheck.Port = 443
                        try {
                            $iwrParamsInitialCheck.Uri = $httpsUriBuilderCheck.Uri.AbsoluteUri
                            $responseObject = Invoke-WebRequest @iwrParamsInitialCheck -SslProtocol Tls12
                            $initialVersionCheckSuccess = $true
                        } catch {
                            $CaughtErrorICR = $_ # ICR for Initial Check Routines
                            Write-Log -Message ("Initial check for {0}: HTTPS failed ({1}). Falling back to HTTP." -f $msIP, $CaughtErrorICR.Exception.Message.Split([Environment]::NewLine)[0]) -Level DEBUG
                            $iwrParamsInitialCheck.Uri = $versionUriForCheck # Revert to original HTTP URI
                            if ($credential -and $PSVersionTable.PSVersion.Major -ge 6) { $iwrParamsInitialCheck.AllowUnencryptedAuthentication = $true }
                            $responseObject = Invoke-WebRequest @iwrParamsInitialCheck # This will throw to the outer IWR catch if it fails
                            $initialVersionCheckSuccess = $true
                        }
                    } else { # Scheme was HTTPS
                        $invokeWebRequestSplatHttp = $iwrParamsInitialCheck
                        # Ensure SslProtocol Tls12 is used for HTTPS if on PS 6+ (already in iwrParams for PS5 via SecurityProtocol global)
                        # For PS Core, Invoke-WebRequest might need explicit -SslProtocol if not relying on global.
                        # However, the global [System.Net.ServicePointManager]::SecurityProtocol should cover it.
                        # Adding it explicitly for PS6+ for robustness if needed, though original logic didn't differentiate here.
                        if ($PSVersionTable.PSVersion.Major -ge 6) {
                             $invokeWebRequestSplatHttp = $iwrParamsInitialCheck | Add-Member -MemberType NoteProperty -Name SslProtocol -Value Tls12 -PassThru -Force
                        }
                        $responseObject = Invoke-WebRequest @invokeWebRequestSplatHttp
                        $initialVersionCheckSuccess = $true
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
                Write-Log -Message ("MS '{0}' is already at desired version '{1}'." -f $msIP, $DesiredVersion) -Level INFO
                $msStatusObject.StatusMessage = "AlreadyUpToDate"; $msStatusObject.VersionAfterUpdate = $currentNormalizedVersion; $msStatusObject.UpdateSucceeded = $true
            } else {
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
                    Credential             = $credential
                    StepNumber             = $StepNumber # Pass overall step number
                    TotalSteps             = $TotalSteps   # Pass overall total steps
                    IsInteractive          = $IsInteractive
                    ErrorOccurred          = $script:ErrorOccurredInUpdateMS
                    AnyUpdatePerformed     = ($allMSResults.UpdateSucceeded -contains $true)
                    SkipCertificateCheck   = $SkipCertificateCheck.IsPresent
                    MSCounter              = $msCounter # For Invoke-MSUpdate to use in its toast
                    TotalMS                = $MSs.Count  # For Invoke-MSUpdate to use in its toast
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
    Exit-Function
}
Write-Log -Message ("Update-MS returning {0} results. Overall Error: {1}" -f $allMSResults.Count, $script:ErrorOccurredInUpdateMS) -Level INFO
return $allMSResults
return $allMSResults
}

function Invoke-MSUpdate {
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$MSUri,
    [Parameter(Mandatory=$true)][string]$NormalizedDesiredVersion,
    [Parameter()][System.Management.Automation.PSCredential]$Credential = $null,
    [Parameter(Mandatory = $false)][int]$StepNumber = 1,
    [Parameter(Mandatory = $false)][int]$TotalSteps = 1,
    [Parameter()][bool]$IsInteractive = $false,
    [Parameter()][bool]$ErrorOccurred = $false,
    [Parameter()][bool]$AnyUpdatePerformed = $false,
    [Parameter()][switch]$SkipCertificateCheck,
    [Parameter(Mandatory = $false)][int]$MSCounter = 1, # Current MS being processed
    [Parameter(Mandatory = $false)][int]$TotalMS = 1    # Total MS in this batch
)
Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber

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
        $triggerParams = @{ Uri = $MSUri; Method = 'Get'; TimeoutSec = 30; ErrorAction = 'Stop' }
        if ($Credential) {
            if ($schemeInInvoke -eq 'http' -and $PSVersionTable.PSVersion.Major -ge 6) {
                $triggerParams.Credential = $Credential; $triggerParams.AllowUnencryptedAuthentication = $true
            } elseif ($schemeInInvoke -eq 'http') {
                $Username = $Credential.UserName; $Password = $Credential.GetNetworkCredential().Password
                $EncodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
                $triggerParams.Headers = @{ Authorization = "Basic $EncodedCredentials" }
            } else {
                $triggerParams.Credential = $Credential
            }
        }
        Invoke-WebRequest @triggerParams | Out-Null
        Write-Log -Message ("Update trigger sent to '{0}'." -f $hostForPingInInvoke) -Level INFO
        $invokeResult.StatusMessage = "UpdateTriggered_WaitingForReboot"
    } catch {
        $CaughtError = $_
        $invokeResult.ErrorOccurredInInvoke = $true; $invokeResult.StatusMessage = ("Error_TriggeringUpdate: {0}" -f $CaughtError.Exception.Message.Split([Environment]::NewLine)[0])
        Write-Log -Message ("Error triggering update for '{0}': {1}" -f $hostForPingInInvoke, $CaughtError.Exception.Message) -Level ERROR
    }

    if (-not $invokeResult.ErrorOccurredInInvoke) {
        Write-Log -Message ("Waiting for MS {0} to reboot/update..." -f $hostForPingInInvoke) -Level INFO
        $toastStepNameWait = "Step $($StepNumber)/$($TotalSteps): Updating MS $($MSCounter)/$($TotalMS) - Waiting for $($hostForPingInInvoke)..."
        Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName $toastStepNameWait -IsInteractive $IsInteractive -ErrorOccurred $ErrorOccurred -AnyUpdatePerformed $AnyUpdatePerformed
        
        $startTime = Get-Date; $timeout = New-TimeSpan -Minutes 15; $msResponsive = $false; $loggedUpdatingStatus = $false
        $verifyParams = @{ Uri = $verificationUriForPolling; UseBasicParsing = $true; TimeoutSec = 10; ErrorAction = 'Stop' }
        if ($Credential) {
            if ($schemeInInvoke -eq 'http' -and $PSVersionTable.PSVersion.Major -ge 6) {
                $verifyParams.Credential = $Credential; $verifyParams.AllowUnencryptedAuthentication = $true
            } elseif ($schemeInInvoke -eq 'http') {
                $Username = $Credential.UserName; $Password = $Credential.GetNetworkCredential().Password
                $EncodedCredentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
                $verifyParams.Headers = @{ Authorization = "Basic $EncodedCredentials" }
            } else {
                $verifyParams.Credential = $Credential
            }
        }

        $Attempts = 0; $MaxAttempts = [Math]::Floor($timeout.TotalSeconds / 10)
        $LastPollStatusMessage = "Initiating..."
        while (((Get-Date) - $startTime) -lt $timeout) {
            $Attempts++; Write-Host -NoNewline ("`rPolling MS $hostForPingInInvoke (Attempt $Attempts/$MaxAttempts): $LastPollStatusMessage".PadRight(120)); Start-Sleep -Seconds 10
            try {
                $lastResponse = Invoke-WebRequest @verifyParams
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
            Write-Log -Message ("MS {0} WebException during poll ({1}): {2}" -f $hostForPingInInvoke, $LastPollStatusMessage, $currentWebError.Exception.Message.Split([Environment]::NewLine)[0]) -Level WARN
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
    Write-Log -Message "Restoring original SSL/TLS certificate validation callback for ${hostForPingInInvoke} in Invoke-MSUpdate." -Level DEBUG
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
}
}
return $invokeResult
}