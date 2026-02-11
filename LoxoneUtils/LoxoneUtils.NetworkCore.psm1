# NetworkCore Module - Abstraction layer for network operations
# Provides fast network operations for testing while maintaining production compatibility

# Load required assemblies
try {
    Add-Type -AssemblyName System.Net.Http
} catch {
    Write-Verbose "System.Net.Http assembly already loaded or not available"
}

# Script-level variables for singleton pattern
$script:httpClientInstance = $null
$script:httpClientLock = New-Object System.Object
$script:isTestMode = $false

# Initialize module state
function Initialize-NetworkCore {
    [CmdletBinding()]
    param()
    
    # Detect if we're in test mode
    $script:isTestMode = (
        $env:LOXONE_USE_FAST_NETWORK -eq "1" -or 
        $env:PESTER_TEST_RUN -eq "1" -or
        $env:LOXONE_TEST_MODE -eq "1"
    )
    
    if ($script:isTestMode) {
        Write-Verbose "NetworkCore: Fast network mode enabled for testing"
    }
}

# Get or create singleton HttpClient instance
function Get-NetworkClient {
    [CmdletBinding()]
    param()
    
    if ($null -eq $script:httpClientInstance) {
        [System.Threading.Monitor]::Enter($script:httpClientLock)
        try {
            if ($null -eq $script:httpClientInstance) {
                Write-Verbose "Creating new HttpClient instance"
                
                # Load System.Net.Http assembly if not already loaded
                try {
                    Add-Type -AssemblyName System.Net.Http
                } catch {
                    Write-Verbose "System.Net.Http assembly already loaded or not available"
                }
                
                # Create handler with appropriate settings
                $handler = New-Object System.Net.Http.HttpClientHandler
                $handler.ServerCertificateCustomValidationCallback = { $true }  # Accept all certs in test
                $handler.AllowAutoRedirect = $false
                $handler.UseProxy = $false  # Disable proxy for speed
                
                # Create HttpClient with handler
                $script:httpClientInstance = New-Object System.Net.Http.HttpClient($handler)
                
                # Set default timeout (can be overridden per request)
                $script:httpClientInstance.Timeout = [System.TimeSpan]::FromMilliseconds(5000)
                
                # Set default headers
                $script:httpClientInstance.DefaultRequestHeaders.Add("User-Agent", "LoxoneUtils-NetworkCore/1.0")
            }
        }
        finally {
            [System.Threading.Monitor]::Exit($script:httpClientLock)
        }
    }
    
    return $script:httpClientInstance
}

# Fast network endpoint test using HttpClient
function Test-FastNetworkEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter()]
        [int]$TimeoutMs = 100,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    $client = Get-NetworkClient
    $cts = New-Object System.Threading.CancellationTokenSource([System.TimeSpan]::FromMilliseconds($TimeoutMs))
    
    try {
        # Create request
        $request = New-Object System.Net.Http.HttpRequestMessage
        $request.Method = [System.Net.Http.HttpMethod]::Get
        $request.RequestUri = [System.Uri]::new($Uri)
        
        # Add credentials if provided
        if ($Credential) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes("$($Credential.UserName):$($Credential.GetNetworkCredential().Password)")
            $base64 = [System.Convert]::ToBase64String($bytes)
            $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Basic", $base64)
        }
        
        # Send request with timeout
        $task = $client.SendAsync($request, $cts.Token)
        
        if ($task.Wait($TimeoutMs)) {
            $response = $task.Result
            
            # Read content if available
            $content = ""
            if ($response.Content) {
                $contentTask = $response.Content.ReadAsStringAsync()
                if ($contentTask.Wait($TimeoutMs)) {
                    $content = $contentTask.Result
                }
            }
            
            return @{
                Success = $true
                StatusCode = [int]$response.StatusCode
                ReasonPhrase = $response.ReasonPhrase
                Content = $content
            }
        }
        else {
            return @{
                Success = $false
                StatusCode = 0
                Error = "Request timed out after ${TimeoutMs}ms"
            }
        }
    }
    catch {
        return @{
            Success = $false
            StatusCode = 0
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($request) { $request.Dispose() }
        if ($cts) { $cts.Dispose() }
    }
}

# Standard network test using Invoke-WebRequest
function Test-StandardNetworkEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter()]
        [int]$TimeoutSec = 15,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    try {
        $params = @{
            Uri = $Uri
            TimeoutSec = $TimeoutSec
            UseBasicParsing = $true
            ErrorAction = 'Stop'
        }
        
        if ($Credential) {
            $params.Credential = $Credential
            # PS7 requires AllowUnencryptedAuthentication for HTTP credentials
            if ($PSVersionTable.PSVersion.Major -ge 6 -and $Uri -match '^http://') {
                $params.AllowUnencryptedAuthentication = $true
            }
        }

        $response = Invoke-WebRequest @params
        
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            ReasonPhrase = $response.StatusDescription
            Content = $response.Content
        }
    }
    catch {
        return @{
            Success = $false
            StatusCode = 0
            Error = $_.Exception.Message
        }
    }
}

# Main abstraction function - chooses appropriate implementation
function Invoke-NetworkRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter()]
        [int]$TimeoutMs,
        
        [Parameter()]
        [int]$TimeoutSec,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [switch]$ForceStandard,
        
        [Parameter()]
        [switch]$ForceFast
    )
    
    # Determine which implementation to use
    $useFastMode = $false
    
    if ($ForceFast) {
        $useFastMode = $true
    }
    elseif ($ForceStandard) {
        $useFastMode = $false
    }
    elseif ($script:isTestMode -and -not $ForceStandard) {
        $useFastMode = $true
    }
    
    if ($useFastMode) {
        # Use fast HttpClient implementation
        $timeout = if ($TimeoutMs -and $TimeoutMs -gt 0) { $TimeoutMs } 
                  elseif ($TimeoutSec -and $TimeoutSec -gt 0) { $TimeoutSec * 1000 } 
                  else { 1000 }
        
        Write-Verbose "Using fast network mode with ${timeout}ms timeout"
        return Test-FastNetworkEndpoint -Uri $Uri -TimeoutMs $timeout -Credential $Credential
    }
    else {
        # Use standard Invoke-WebRequest
        $timeout = if ($TimeoutSec -and $TimeoutSec -gt 0) { $TimeoutSec } 
                  elseif ($TimeoutMs -and $TimeoutMs -gt 0) { [Math]::Max(1, [Math]::Ceiling($TimeoutMs / 1000.0)) } 
                  else { 5 }
        
        Write-Verbose "Using standard network mode with ${timeout}s timeout"
        return Test-StandardNetworkEndpoint -Uri $Uri -TimeoutSec $timeout -Credential $Credential
    }
}

# Test network connectivity with fast timeout
function Test-NetworkEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter()]
        [int]$TimeoutMs = 1000,
        
        [Parameter()]
        [PSCredential]$Credential
    )
    
    return Invoke-NetworkRequest -Uri $Uri -TimeoutMs $TimeoutMs -Credential $Credential
}

# Cleanup function for module unload
function Clear-NetworkCore {
    [CmdletBinding()]
    param()
    
    if ($script:httpClientInstance) {
        Write-Verbose "Disposing HttpClient instance"
        $script:httpClientInstance.Dispose()
        $script:httpClientInstance = $null
    }
}

# Initialize on module load
Initialize-NetworkCore

# Export functions
Export-ModuleMember -Function @(
    'Initialize-NetworkCore',
    'Invoke-NetworkRequest',
    'Test-NetworkEndpoint',
    'Test-FastNetworkEndpoint',
    'Test-StandardNetworkEndpoint',
    'Clear-NetworkCore'
)