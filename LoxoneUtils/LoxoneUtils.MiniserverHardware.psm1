#Requires -Module LoxoneUtils.Logging

<#
.SYNOPSIS
Functions for detecting Loxone Miniserver hardware generation and capabilities

.DESCRIPTION
Provides functions to query and detect Miniserver hardware information including:
- Generation (Gen1 grey case, Gen1 green case, Gen2)
- Hardware ID
- Serial number
- HTTPS requirements
#>

function Get-MiniserverHardwareInfo {
    <#
    .SYNOPSIS
    Gets hardware information from a Loxone Miniserver
    
    .DESCRIPTION
    Queries the Miniserver's UPNP endpoint or version info to determine hardware details
    
    .PARAMETER MSEntry
    The miniserver connection string (e.g., http://user:pass@192.168.1.100)
    
    .PARAMETER SkipCertificateCheck
    Skip certificate validation for HTTPS connections
    
    .PARAMETER TimeoutSec
    Timeout in seconds for the request
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSEntry,
        
        [Parameter()]
        [switch]$SkipCertificateCheck,
        
        [Parameter()]
        [int]$TimeoutSec = 5
    )
    
    $result = @{
        Success = $false
        Generation = "Unknown"
        HardwareId = ""
        SerialNumber = ""
        RequiresHTTPS = $false
        Error = $null
        DetectionMethod = ""
    }
    
    try {
        # Parse the MS entry to get the base URL
        $uri = [System.Uri]$MSEntry
        $baseUrl = "$($uri.Scheme)://$($uri.Host)"
        if ($uri.Port -ne 80 -and $uri.Port -ne 443) {
            $baseUrl += ":$($uri.Port)"
        }
        
        # Method 1: Try UPNP endpoint (works on all generations)
        $upnpUrl = "$baseUrl/upnp.xml"
        Write-Log -Message "Attempting to get hardware info from UPNP: $upnpUrl" -Level DEBUG
        
        try {
            $upnpParams = @{
                Uri = $upnpUrl
                TimeoutSec = $TimeoutSec
                UseBasicParsing = $true
                ErrorAction = 'Stop'
            }

            if ($SkipCertificateCheck) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $upnpParams.SkipCertificateCheck = $true
                } else {
                    $null = Set-CertificateValidationBypass
                    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                }
            }

            # Add credentials if provided
            if ($uri.UserInfo) {
                $userPass = $uri.UserInfo.Split(':')
                if ($userPass.Count -eq 2) {
                    $securePassword = New-Object System.Security.SecureString
                    foreach ($c in $userPass[1].ToCharArray()) { $securePassword.AppendChar($c) }
                    $credential = New-Object System.Management.Automation.PSCredential($userPass[0], $securePassword)
                    $upnpParams.Credential = $credential
                    # PS7 requires AllowUnencryptedAuthentication for HTTP credentials
                    if ($PSVersionTable.PSVersion.Major -ge 6 -and $uri.Scheme -eq 'http') {
                        $upnpParams.AllowUnencryptedAuthentication = $true
                    }
                }
            }

            $response = Invoke-WebRequest @upnpParams

            if ($response.Content -match '<serialNumber>([^<]+)</serialNumber>') {
                $result.SerialNumber = $Matches[1]
                Write-Log -Message "Found serial number: $($result.SerialNumber)" -Level DEBUG
            }

            if ($response.Content -match '<modelNumber>([^<]+)</modelNumber>') {
                $modelNumber = $Matches[1]
                Write-Log -Message "Found model number: $modelNumber" -Level DEBUG
            }

            $result.DetectionMethod = "UPNP"
            $result.Success = $true

        } catch {
            Write-Log -Message "UPNP query failed: $_" -Level DEBUG
        } finally {
            if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
                $null = Clear-CertificateValidationBypass
            }
        }

        # Method 2: Try UDP discovery (if we can determine from other info)
        # This would require UDP support which is more complex

        # Method 3: Use version endpoint response characteristics
        if (-not $result.Success) {
            try {
                # Try to get version info - the response format can indicate generation
                $versionUrl = "$baseUrl/dev/cfg/version"
                Write-Log -Message "Attempting to get hardware info from version endpoint: $versionUrl" -Level DEBUG

                $versionParams = @{
                    Uri = $versionUrl
                    TimeoutSec = $TimeoutSec
                    UseBasicParsing = $true
                    ErrorAction = 'Stop'
                }

                if ($SkipCertificateCheck) {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        $versionParams.SkipCertificateCheck = $true
                    } else {
                        $null = Set-CertificateValidationBypass
                        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                    }
                }

                # Add credentials if provided
                if ($uri.UserInfo) {
                    $userPass = $uri.UserInfo.Split(':')
                    if ($userPass.Count -eq 2) {
                        $securePassword = New-Object System.Security.SecureString
                        foreach ($c in $userPass[1].ToCharArray()) { $securePassword.AppendChar($c) }
                        $credential = New-Object System.Management.Automation.PSCredential($userPass[0], $securePassword)
                        $versionParams.Credential = $credential
                        if ($PSVersionTable.PSVersion.Major -ge 6 -and $uri.Scheme -eq 'http') {
                            $versionParams.AllowUnencryptedAuthentication = $true
                        }
                    }
                }

                $versionResponse = Invoke-WebRequest @versionParams

                # Parse version info for clues
                if ($versionResponse.Content) {
                    Write-Log -Message "Got version response, analyzing..." -Level DEBUG
                    $result.DetectionMethod = "VersionAnalysis"
                    $result.Success = $true
                }

            } catch {
                Write-Log -Message "Version endpoint query failed: $_" -Level DEBUG
            } finally {
                if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
                    $null = Clear-CertificateValidationBypass
                }
            }
        }
        
        # Determine generation based on collected info
        $result.Generation = Get-MiniserverGeneration -SerialNumber $result.SerialNumber -HardwareId $result.HardwareId -MSEntry $MSEntry
        
        # Gen2 requires HTTPS
        if ($result.Generation -eq "Gen2") {
            $result.RequiresHTTPS = $true
        }
        
    } catch {
        $result.Error = $_.ToString()
        Write-Log -Message "Error getting hardware info: $_" -Level WARN
    }
    
    return $result
}

function Get-MiniserverGeneration {
    <#
    .SYNOPSIS
    Determines the Miniserver generation based on available information
    
    .DESCRIPTION
    Uses serial number patterns, hardware IDs, and connection behavior to determine generation
    #>
    [CmdletBinding()]
    param(
        [string]$SerialNumber,
        [string]$HardwareId,
        [string]$MSEntry
    )
    
    # Based on user's information:
    # 192.168.178.2 = Gen1 grey case (oldest)
    # 192.168.2.210 = Gen1 green case
    # 10.3.98.5 = Gen2
    
    # Gen2 detection patterns:
    # - Requires HTTPS (won't work on HTTP)
    # - Different serial number pattern
    # - Different hardware ID pattern
    
    # Check if HTTPS is in the entry
    if ($MSEntry -match '^https://') {
        Write-Log -Message "HTTPS entry detected - likely Gen2" -Level DEBUG
        return "Gen2"
    }
    
    # Check serial number patterns (if available)
    if ($SerialNumber) {
        # Gen2 typically has different serial patterns
        # This is a placeholder - actual patterns need to be determined
        if ($SerialNumber -match '^5[0-9A-F]{11}$') {
            # Classic serial pattern - likely Gen1
            return "Gen1"
        }
    }
    
    # Check hardware ID patterns (if available)
    if ($HardwareId) {
        if ($HardwareId -match '^A0000$') {
            return "Gen1-Grey"  # Oldest version
        }
        # Add more hardware ID patterns as discovered
    }
    
    # Default fallback
    return "Unknown"
}

function Test-MiniserverRequiresHTTPS {
    <#
    .SYNOPSIS
    Tests if a Miniserver requires HTTPS (Gen2)
    
    .DESCRIPTION
    Attempts to connect via HTTP and HTTPS to determine if HTTPS is required
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSEntry,
        
        [Parameter()]
        [int]$TimeoutSec = 3
    )
    
    try {
        # Parse the entry
        $uri = [System.Uri]$MSEntry
        $host = $uri.Host
        
        # Test HTTP
        $httpUrl = "http://$host/dev/cfg/version"
        $httpWorks = $false
        
        try {
            $httpParams = @{
                Uri = $httpUrl
                TimeoutSec = $TimeoutSec
                UseBasicParsing = $true
                ErrorAction = 'Stop'
            }

            $httpResponse = Invoke-WebRequest @httpParams
            if ($httpResponse.StatusCode -eq 200) {
                $httpWorks = $true
                Write-Log -Message "HTTP works for ${host} - likely Gen1" -Level DEBUG
            }
        } catch {
            Write-Log -Message "HTTP failed for ${host}: $_" -Level DEBUG
        }
        
        # Test HTTPS - use HttpWebRequest directly for PS 5.1 compatibility
        # (Invoke-WebRequest in PS 5.1 has ServicePoint cache issues with cert bypass)
        $httpsUrl = "https://$host/dev/cfg/version"
        $httpsWorks = $false

        try {
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $httpsParams = @{
                    Uri = $httpsUrl
                    TimeoutSec = $TimeoutSec
                    UseBasicParsing = $true
                    ErrorAction = 'Stop'
                    SkipCertificateCheck = $true
                }
                try {
                    $httpsResponse = Invoke-WebRequest @httpsParams
                    $httpsWorks = $true
                    Write-Log -Message "HTTPS works for ${host} (status $($httpsResponse.StatusCode))" -Level DEBUG
                } catch {
                    # Any HTTP error response (401, 403, etc.) still means HTTPS works
                    if ($_.Exception.Response) {
                        $httpsWorks = $true
                        Write-Log -Message "HTTPS works for ${host} (got HTTP error, but connection succeeded)" -Level DEBUG
                    } else {
                        throw
                    }
                }
            } else {
                $null = Set-CertificateValidationBypass
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls

                # Clear any poisoned ServicePoint cache from prior failed SSL connections
                try {
                    $sp = [System.Net.ServicePointManager]::FindServicePoint([System.Uri]$httpsUrl)
                    $null = $sp.CloseConnectionGroup("")
                } catch {
                    Write-Log -Message "Could not reset ServicePoint for ${host}: $_" -Level DEBUG
                }

                $request = [System.Net.HttpWebRequest]::Create($httpsUrl)
                $request.Method = "GET"
                $request.Timeout = $TimeoutSec * 1000
                # Use unique connection group to avoid poisoned SSL session cache
                $request.ConnectionGroupName = "TestHTTPS_" + [Guid]::NewGuid().ToString()

                try {
                    $response = $request.GetResponse()
                    $response.Close()
                    $httpsWorks = $true
                    Write-Log -Message "HTTPS works for ${host}" -Level DEBUG
                } catch {
                    # PowerShell wraps .NET exceptions in MethodInvocationException
                    # Check inner WebException for an HTTP response (401, 403 = connection works)
                    $webEx = $_.Exception
                    while ($webEx -and $webEx -isnot [System.Net.WebException]) {
                        $webEx = $webEx.InnerException
                    }
                    if ($webEx -and $webEx.Response) {
                        $httpsWorks = $true
                        Write-Log -Message "HTTPS works for ${host} (got HTTP $([int]$webEx.Response.StatusCode), but connection succeeded)" -Level DEBUG
                    } else {
                        throw
                    }
                }
            }
        } catch {
            Write-Log -Message "HTTPS failed for ${host}: $_" -Level DEBUG
        } finally {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                $null = Clear-CertificateValidationBypass
            }
        }
        
        # Determine based on results
        if (-not $httpWorks -and $httpsWorks) {
            Write-Log -Message "${host} requires HTTPS - likely Gen2" -Level INFO
            return $true
        } elseif ($httpWorks) {
            Write-Log -Message "${host} works with HTTP - likely Gen1" -Level INFO
            return $false
        } else {
            Write-Log -Message "Could not determine HTTPS requirement for ${host}" -Level WARN
            return $false
        }
        
    } catch {
        Write-Log -Message "Error testing HTTPS requirement: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function @(
    'Get-MiniserverHardwareInfo',
    'Get-MiniserverGeneration',
    'Test-MiniserverRequiresHTTPS'
)