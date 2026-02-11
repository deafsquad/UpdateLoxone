#Requires -Module LoxoneUtils.Logging, LoxoneUtils.MiniserverCache

<#
.SYNOPSIS
Functions for detecting and caching Loxone Miniserver hardware generation

.DESCRIPTION
Detects hardware generation based on:
- 192.168.178.2 = Gen1 grey case (oldest revision)  
- 192.168.2.210 = Gen1 green case
- 10.3.98.5 = Gen2 (requires HTTPS)
#>

function Get-MiniserverGenerationInfo {
    <#
    .SYNOPSIS
    Determines the hardware generation of a Miniserver
    
    .DESCRIPTION
    Uses /data/status endpoint to get Type field and MAC address:
    - Gen1-Grey: Type=0, MAC prefix EEE0 (oldest grey case hardware)
    - Gen1-Green: Type=0, MAC prefix 504F (green case hardware)
    - Gen2: Type=2 (latest generation, requires HTTPS)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSEntry,
        
        [Parameter()]
        [switch]$ForceRefresh,
        
        [Parameter()]
        [int]$TimeoutSec = 3
    )
    
    $result = @{
        Generation = "Unknown"
        Description = "Unknown hardware generation"
        RequiresHTTPS = $false
        DetectionMethod = "Unknown"
        Success = $false
        Error = $null
    }
    
    try {
        # Parse the entry - handle special characters in password
        $host = $null
        $userInfo = $null
        
        if ($MSEntry -match '^(https?://)?([^:]+):([^@]+)@([^/,]+)') {
            $scheme = if ($matches[1]) { $matches[1].TrimEnd('://') } else { 'http' }
            $user = $matches[2]
            $pass = $matches[3]
            $host = $matches[4]
            $userInfo = "${user}:${pass}"
            Write-Log -Message "Parsed: host=$host, user=$user" -Level DEBUG
        } else {
            # Fallback to URI parsing
            $uri = [System.Uri]$MSEntry
            $userInfo = $uri.UserInfo
            $host = $uri.Host
            $scheme = $uri.Scheme
        }
        
        Write-Log -Message "Detecting generation for MS at $host" -Level DEBUG
        
        # Try /data/status endpoint which gives us Type and MAC
        try {
            # Prepare authentication
            $base64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($userInfo))
            
            # Try HTTP first (works for Gen1)
            $statusUrl = "http://${host}/data/status"
            $response = $null
            
            try {
                Write-Log -Message "Trying HTTP status endpoint" -Level DEBUG
                
                $request = [System.Net.HttpWebRequest]::Create($statusUrl)
                $request.Method = "GET"
                $request.Timeout = $TimeoutSec * 1000
                $request.Headers.Add("Authorization", "Basic $base64")
                
                $response = $request.GetResponse()
                $stream = $response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $content = $reader.ReadToEnd()
                
                $reader.Close()
                $stream.Close()
                $response.Close()
            } catch {
                # If HTTP fails, try HTTPS (Gen2)
                Write-Log -Message "HTTP failed, trying HTTPS" -Level DEBUG
                
                $statusUrl = "https://${host}/data/status"
                
                # Set up certificate bypass for self-signed certs
                Set-CertificateValidationBypass
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
                
                $request = [System.Net.HttpWebRequest]::Create($statusUrl)
                $request.Method = "GET"
                $request.Timeout = $TimeoutSec * 1000
                $request.Headers.Add("Authorization", "Basic $base64")
                
                $response = $request.GetResponse()
                $stream = $response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $content = $reader.ReadToEnd()
                
                $reader.Close()
                $stream.Close()
                $response.Close()
                
                Clear-CertificateValidationBypass
            }
            
            if ($content) {
                # Remove BOM if present
                if ($content.StartsWith([char]0xEF + [char]0xBB + [char]0xBF)) {
                    $content = $content.Substring(3)
                }
                
                [xml]$xml = $content
                $miniserver = $xml.Status.Miniserver
                
                $type = [int]$miniserver.Type
                $mac = $miniserver.MAC
                $device = $miniserver.Device
                
                Write-Log -Message "Got Type=$type, MAC=$mac, Device=$device" -Level DEBUG
                
                # Determine generation based on Type and MAC
                if ($type -eq 2) {
                    # Type 2 is Gen2
                    $result.Generation = "Gen2"
                    $result.Description = "Generation 2 - Latest Hardware (Type 2)"
                    $result.RequiresHTTPS = $true
                    $result.DetectionMethod = "Status-Type2"
                    $result.Success = $true
                    Write-Log -Message "Detected Gen2 based on Type=2" -Level INFO
                } elseif ($type -eq 0) {
                    # Type 0 is Gen1, check MAC to distinguish Grey vs Green
                    $macPrefix = $mac.Substring(0, 4).ToUpper()
                    
                    if ($macPrefix -eq 'EEE0') {
                        $result.Generation = "Gen1-Grey"
                        $result.Description = "Generation 1 - Grey Case (Type 0, MAC: EEE0)"
                        $result.RequiresHTTPS = $false
                        $result.DetectionMethod = "Status-Type0-MacEEE0"
                        $result.Success = $true
                        Write-Log -Message "Detected Gen1-Grey based on Type=0 and MAC prefix EEE0" -Level INFO
                    } else {
                        $result.Generation = "Gen1-Green"
                        $result.Description = "Generation 1 - Green Case (Type 0, MAC: $macPrefix)"
                        $result.RequiresHTTPS = $false
                        $result.DetectionMethod = "Status-Type0-Mac504F"
                        $result.Success = $true
                        Write-Log -Message "Detected Gen1-Green based on Type=0 and MAC prefix $macPrefix" -Level INFO
                    }
                } else {
                    # Unknown type
                    Write-Log -Message "Unknown Miniserver Type: $type" -Level WARN
                    $result.Generation = "Unknown"
                    $result.Description = "Unknown Type: $type"
                }
                
                return $result
            }
        } catch {
            Write-Log -Message "Could not get status info: $_" -Level DEBUG
        } finally {
            Clear-CertificateValidationBypass
        }
        
        # For unknown IPs, try to detect based on behavior
        Write-Log -Message "Unknown IP, attempting behavior-based detection" -Level DEBUG
        
        # Parse the URI
        $uri = [System.Uri]$MSEntry
        $host = $uri.Host
        
        # Test HTTP connectivity
        $httpWorks = $false
        $httpsWorks = $false
        
        try {
            $httpUrl = "http://$host/dev/cfg/version"
            $httpParams = @{
                Uri = $httpUrl
                TimeoutSec = $TimeoutSec
                UseBasicParsing = $true
                ErrorAction = 'Stop'
            }
            
            # Add credentials if available
            if ($uri.UserInfo) {
                $userPass = $uri.UserInfo.Split(':')
                if ($userPass.Count -eq 2) {
                    $securePassword = New-Object System.Security.SecureString
                    foreach ($c in $userPass[1].ToCharArray()) { $securePassword.AppendChar($c) }
                    $credential = New-Object System.Management.Automation.PSCredential($userPass[0], $securePassword)
                    $httpParams.Credential = $credential
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        $httpParams.AllowUnencryptedAuthentication = $true
                    }
                }
            }

            $httpResponse = Invoke-WebRequest @httpParams
            if ($httpResponse.StatusCode -eq 200) {
                $httpWorks = $true
                Write-Log -Message "HTTP connection successful" -Level DEBUG
            }
        } catch {
            Write-Log -Message "HTTP connection failed: $_" -Level DEBUG
        }
        
        # Test HTTPS connectivity
        try {
            $httpsUrl = "https://$host/dev/cfg/version"
            $httpsParams = @{
                Uri = $httpsUrl
                TimeoutSec = $TimeoutSec
                UseBasicParsing = $true
                ErrorAction = 'Stop'
            }
            
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $httpsParams.SkipCertificateCheck = $true
            }
            
            # Add credentials if available
            if ($uri.UserInfo) {
                $userPass = $uri.UserInfo.Split(':')
                if ($userPass.Count -eq 2) {
                    $securePassword = New-Object System.Security.SecureString
                    foreach ($c in $userPass[1].ToCharArray()) { $securePassword.AppendChar($c) }
                    $credential = New-Object System.Management.Automation.PSCredential($userPass[0], $securePassword)
                    $httpsParams.Credential = $credential
                }
            }
            
            # For older PowerShell, ignore SSL errors
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                Set-CertificateValidationBypass
            }
            
            $httpsResponse = Invoke-WebRequest @httpsParams
            if ($httpsResponse.StatusCode -eq 200) {
                $httpsWorks = $true
                Write-Log -Message "HTTPS connection successful" -Level DEBUG
            }
        } catch {
            Write-Log -Message "HTTPS connection failed: $_" -Level DEBUG
        } finally {
            # Reset certificate validation
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                Clear-CertificateValidationBypass
            }
        }
        
        # Determine generation based on connectivity
        if (-not $httpWorks -and $httpsWorks) {
            $result.Generation = "Gen2"
            $result.Description = "Generation 2 - HTTPS Required"
            $result.RequiresHTTPS = $true
            $result.DetectionMethod = "BehaviorHTTPSOnly"
            $result.Success = $true
        } elseif ($httpWorks -and -not $httpsWorks) {
            $result.Generation = "Gen1-Grey"
            $result.Description = "Generation 1 - Grey Case (HTTP Only)"
            $result.RequiresHTTPS = $false
            $result.DetectionMethod = "BehaviorHTTPOnly"
            $result.Success = $true
        } elseif ($httpWorks -and $httpsWorks) {
            $result.Generation = "Gen1-Green"
            $result.Description = "Generation 1 - Green Case (HTTP/HTTPS)"
            $result.RequiresHTTPS = $false
            $result.DetectionMethod = "BehaviorBothProtocols"
            $result.Success = $true
        } else {
            $result.Error = "Could not connect via HTTP or HTTPS"
            Write-Log -Message "Could not determine generation - no connectivity" -Level WARN
        }
        
    } catch {
        $result.Error = $_.ToString()
        Write-Log -Message "Error detecting generation: $_" -Level ERROR
    }
    
    return $result
}

function Update-MiniserverGenerationCache {
    <#
    .SYNOPSIS
    Updates the generation info in the cache file
    
    .DESCRIPTION
    Checks if generation info needs updating (weekly) and updates if necessary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$MSEntry,
        
        [Parameter()]
        [switch]$ForceRefresh
    )
    
    try {
        # Load current cache
        $entries = Get-MiniserverListWithCache -FilePath $FilePath
        
        # Find the matching entry
        $targetEntry = $null
        foreach ($entry in $entries) {
            if ($entry.Url -eq $MSEntry -or $entry.IP -eq $MSEntry) {
                $targetEntry = $entry
                break
            }
        }
        
        if (-not $targetEntry) {
            Write-Log -Message "MS entry not found in cache: $MSEntry" -Level WARN
            return
        }
        
        # Check if generation info needs updating (weekly)
        $needsUpdate = $ForceRefresh
        if (-not $needsUpdate) {
            if (-not $targetEntry.Generation) {
                $needsUpdate = $true
                Write-Log -Message "No generation info cached, will detect" -Level DEBUG
            } elseif ($targetEntry.GenerationLastChecked) {
                $daysSinceCheck = ((Get-Date) - $targetEntry.GenerationLastChecked).TotalDays
                if ($daysSinceCheck -ge 7) {
                    $needsUpdate = $true
                    Write-Log -Message "Generation info is $([int]$daysSinceCheck) days old, will refresh" -Level DEBUG
                }
            } else {
                $needsUpdate = $true
                Write-Log -Message "No generation check timestamp, will detect" -Level DEBUG
            }
        }
        
        if ($needsUpdate) {
            Write-Log -Message "Detecting generation for $($targetEntry.IP)" -Level INFO
            
            # Detect generation
            $genInfo = Get-MiniserverGenerationInfo -MSEntry $targetEntry.Url
            
            if ($genInfo.Success) {
                Write-Log -Message "Detected: $($genInfo.Generation) - $($genInfo.Description)" -Level INFO
                
                # Update the cache file
                $lines = Get-Content $FilePath
                $updatedLines = @()
                $updated = $false
                
                foreach ($line in $lines) {
                    if ($line.Trim().StartsWith('#') -or [string]::IsNullOrWhiteSpace($line)) {
                        $updatedLines += $line
                        continue
                    }
                    
                    $parts = $line.Split(',')
                    $url = $parts[0].Trim()
                    
                    if ($url -eq $targetEntry.Url) {
                        # Update this entry with generation info
                        $version = if ($parts.Length -ge 2) { $parts[1].Trim() } else { "" }
                        $timestamp = if ($parts.Length -ge 3) { $parts[2].Trim() } else { "" }
                        $genTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        
                        $newLine = "$url,$version,$timestamp,$($genInfo.Generation),$genTimestamp"
                        $updatedLines += $newLine
                        $updated = $true
                        Write-Log -Message "Updated cache entry with generation: $($genInfo.Generation)" -Level DEBUG
                    } else {
                        $updatedLines += $line
                    }
                }
                
                if ($updated) {
                    $updatedLines | Set-Content $FilePath -Encoding UTF8
                    Write-Log -Message "Cache file updated with generation info" -Level INFO
                }
            } else {
                Write-Log -Message "Failed to detect generation: $($genInfo.Error)" -Level WARN
            }
        } else {
            Write-Log -Message "Generation info is current: $($targetEntry.Generation)" -Level DEBUG
        }
        
    } catch {
        Write-Log -Message "Error updating generation cache: $_" -Level ERROR
    }
}

Export-ModuleMember -Function @(
    'Get-MiniserverGenerationInfo',
    'Update-MiniserverGenerationCache'
)