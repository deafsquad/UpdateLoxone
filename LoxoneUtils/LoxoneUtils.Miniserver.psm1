# Module for Loxone Update Script MS Interaction Functions

#region MS Update Logic
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
    }

    foreach ($msEntry in $MSs) {
        $redactedEntryForLog = Get-RedactedPassword $msEntry
        Write-Log -Message ("Processing MS entry: {0}" -f $redactedEntryForLog) -Level INFO

        $msIP = $null; $versionUriForCheck = $null; $credential = $null
        $msStatusObject = [PSCustomObject]@{
            MSIP                = "Unknown"; InitialVersion      = "Unknown"; AttemptedUpdate     = $false
            UpdateSucceeded     = $false;    VersionAfterUpdate  = "Unknown"; StatusMessage       = "NotProcessed"
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
                            $CaughtError = $_
                            Write-Log -Message ("Initial check for {0}: HTTPS failed ({1}). Falling back to HTTP." -f $msIP, $CaughtError.Exception.Message.Split([Environment]::NewLine)[0]) -Level DEBUG
                            $iwrParamsInitialCheck.Uri = $versionUriForCheck
                            if ($credential -and $PSVersionTable.PSVersion.Major -ge 6) { $iwrParamsInitialCheck.AllowUnencryptedAuthentication = $true }
                            $responseObject = Invoke-WebRequest @iwrParamsInitialCheck
                            $initialVersionCheckSuccess = $true
                        }
                    } else {
                        $invokeWebRequestSplatHttp = $iwrParamsInitialCheck
                        if ($uriBuilder.Scheme -eq 'https') {
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
                    } else { throw ("Failed to get a valid response for initial version check of MS '{0}'." -f $msIP) }
                } catch {
                    $CaughtError = $_
                    Write-Log -Message ("Error during initial version WebRequest/parsing for {0}: {1}" -f $msIP, $CaughtError.Exception.Message) -Level ERROR; throw
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
                Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName ("Starting update for MS {0}..." -f $msIP) -IsInteractive $IsInteractive -ErrorOccurred $script:ErrorOccurredInUpdateMS -AnyUpdatePerformed ($allMSResults.UpdateSucceeded -contains $true)
                
                $autoupdateUriBuilder = [System.UriBuilder]$entryToParse; $autoupdateUriBuilder.Path = "/dev/sys/autoupdate"
                $uriForUpdateTrigger = $autoupdateUriBuilder.Uri.AbsoluteUri
                
                $invokeParams = @{
                    MSUri = $uriForUpdateTrigger; NormalizedDesiredVersion = $DesiredVersion; Credential = $credential
                    StepNumber = $StepNumber; TotalSteps = $TotalSteps; IsInteractive = $IsInteractive
                    ErrorOccurred = $script:ErrorOccurredInUpdateMS; AnyUpdatePerformed = ($allMSResults.UpdateSucceeded -contains $true)
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
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
            $msStatusObject.MSIP = if ($msIP) { $msIP } else { $redactedEntryForLog }
            $msStatusObject.StatusMessage = ("Error_ProcessingMS_BeforeUpdate: {0}" -f $currentError.Exception.Message.Split([char[]]@("`r","`n"), [System.StringSplitOptions]::RemoveEmptyEntries)[0])
            $msStatusObject.ErrorDuringProcessing = $true; $script:ErrorOccurredInUpdateMS = $true
            Invoke-Command -ScriptBlock { param($Msg, $Lvl) Write-Log -Message $Msg -Level $Lvl } -ArgumentList ("Caught exception for MS '{0}': {1}" -f $msStatusObject.MSIP, $currentError.Exception.Message), "ERROR"
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
    [Parameter()][switch]$SkipCertificateCheck
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
        Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName ("Waiting for MS {0}..." -f $hostForPingInInvoke) -IsInteractive $IsInteractive -ErrorOccurred $ErrorOccurred -AnyUpdatePerformed $AnyUpdatePerformed
        
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
        Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName ("FAILED: MS {0} - {1}" -f $hostForPingInInvoke, $invokeResult.StatusMessage) -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed
    }
}
} catch { # Catch for the main try in Invoke-MSUpdate
$CaughtOuterError = $_
$invokeResult.ErrorOccurredInInvoke = $true
$invokeResult.StatusMessage = ("Error_InvokeMSUpdate_OuterTry: {0}" -f $CaughtOuterError.Exception.Message.Split([Environment]::NewLine)[0])
Write-Log -Message ("Outer error in Invoke-MSUpdate for '{0}': {1}" -f $hostForPingInInvoke, $CaughtOuterError.Exception.Message) -Level ERROR
Update-PersistentToast -StepNumber $StepNumber -TotalSteps $TotalSteps -StepName ("FAILED: Error for MS {0}" -f $hostForPingInInvoke) -IsInteractive $IsInteractive -ErrorOccurred $true -AnyUpdatePerformed $AnyUpdatePerformed
} finally {
$ProgressPreference = $oldProgressPreference
if ($callbackChanged) {
    Write-Log -Message "Restoring original SSL/TLS certificate validation callback for ${hostForPingInInvoke} in Invoke-MSUpdate." -Level DEBUG
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
}
}
return $invokeResult
}