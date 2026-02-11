# Module for Miniserver Version Caching
# Provides intelligent caching to avoid redundant version checks

function ConvertFrom-MiniserverListEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Line
    )
    
    # Skip empty lines and comments
    if ([string]::IsNullOrWhiteSpace($Line) -or $Line.Trim().StartsWith('#')) {
        return $null
    }
    
    # Parse format: URL[,version,timestamp]
    $parts = $Line.Split(',')
    $url = $parts[0].Trim()
    
    $result = @{
        Url = $url
        CachedVersion = $null
        LastChecked = $null
        HasCache = $false
        IP = $null
        Generation = $null
        GenerationLastChecked = $null
    }
    
    # Extract IP from URL
    if ($url -match '@([^/:]+)') {
        $result.IP = $matches[1]
    }
    
    # Parse optional cached version
    if ($parts.Length -ge 2 -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
        $result.CachedVersion = $parts[1].Trim()
        $result.HasCache = $true
    }
    
    # Parse optional timestamp
    if ($parts.Length -ge 3 -and -not [string]::IsNullOrWhiteSpace($parts[2])) {
        $timestampStr = $parts[2].Trim()
        try {
            # Parse format: YYYYMMDD_HHMMSS
            if ($timestampStr -match '^(\d{8})_(\d{6})$') {
                $dateStr = $matches[1]
                $timeStr = $matches[2]
                $year = [int]$dateStr.Substring(0, 4)
                $month = [int]$dateStr.Substring(4, 2)
                $day = [int]$dateStr.Substring(6, 2)
                $hour = [int]$timeStr.Substring(0, 2)
                $minute = [int]$timeStr.Substring(2, 2)
                $second = [int]$timeStr.Substring(4, 2)
                
                $result.LastChecked = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
            }
        } catch {
            Write-Warning "Failed to parse timestamp '$timestampStr' for MS $($result.IP): $($_.Exception.Message)"
        }
    }
    
    # Parse optional generation info (format: generation,genTimestamp)
    if ($parts.Length -ge 4 -and -not [string]::IsNullOrWhiteSpace($parts[3])) {
        $result.Generation = $parts[3].Trim()
    }
    
    # Parse optional generation check timestamp
    if ($parts.Length -ge 5 -and -not [string]::IsNullOrWhiteSpace($parts[4])) {
        $genTimestampStr = $parts[4].Trim()
        try {
            if ($genTimestampStr -match '^(\d{8})_(\d{6})$') {
                $dateStr = $matches[1]
                $timeStr = $matches[2]
                $year = [int]$dateStr.Substring(0, 4)
                $month = [int]$dateStr.Substring(4, 2)
                $day = [int]$dateStr.Substring(6, 2)
                $hour = [int]$timeStr.Substring(0, 2)
                $minute = [int]$timeStr.Substring(2, 2)
                $second = [int]$timeStr.Substring(4, 2)
                
                $result.GenerationLastChecked = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
            }
        } catch {
            Write-Warning "Failed to parse generation timestamp '$genTimestampStr' for MS $($result.IP): $($_.Exception.Message)"
        }
    }
    
    return $result
}

function Test-MiniserverCacheValid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $MSEntry,
        
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [string]$TargetVersion = "",
        
        [Parameter(Mandatory=$false)]
        [int]$MaxCacheAgeHours = 24
    )
    
    # If no target version provided, we're just checking cache age, not version match
    $checkVersionMatch = -not [string]::IsNullOrWhiteSpace($TargetVersion)
    
    # No cache available
    if (-not $MSEntry.HasCache -or -not $MSEntry.CachedVersion) {
        return $false
    }
    
    # Check version match only if target version was provided
    if ($checkVersionMatch -and $MSEntry.CachedVersion -ne $TargetVersion) {
        return $false
    }
    
    # Check cache age if timestamp available
    if ($MSEntry.LastChecked) {
        $now = Get-Date
        $ageHours = ($now - $MSEntry.LastChecked).TotalHours
        
        # Handle future timestamps (clock skew or recent cache update)
        if ($ageHours -lt 0) {
            # If timestamp is in the future but within 1 minute, accept it (clock skew tolerance)
            if ($ageHours -gt -0.0167) { # -1 minute
                Write-Log -Message "MS $($MSEntry.IP) cache has minor future timestamp ($('{0:N2}' -f ($ageHours * 60)) min), accepting" -Level DEBUG
                return $true
            } else {
                Write-Log -Message "MS $($MSEntry.IP) cache has invalid future timestamp ($($MSEntry.LastChecked) vs $now)" -Level WARN
                return $false
            }
        }
        
        # Check if cache is too old
        if ($ageHours -gt $MaxCacheAgeHours) {
            Write-Log -Message "MS $($MSEntry.IP) cache expired (age: $([Math]::Round($ageHours, 1))h, max: ${MaxCacheAgeHours}h)" -Level DEBUG
            return $false
        }
    } else {
        # No timestamp means cache validity unknown - be conservative
        Write-Log -Message "MS $($MSEntry.IP) cache has no timestamp, treating as invalid" -Level DEBUG
        return $false
    }
    
    return $true
}

function Update-MiniserverListCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$IP,
        
        [Parameter(Mandatory=$true)]
        [string]$Version,
        
        [Parameter(Mandatory=$false)]
        [string]$Generation = $null,
        
        [Parameter(Mandatory=$false)]
        [datetime]$Timestamp = (Get-Date)
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Warning "Miniserver list file not found: $FilePath"
        return
    }
    
    try {
        $lines = Get-Content $FilePath
        $updated = $false
        $timestampStr = $Timestamp.ToString("yyyyMMdd_HHmmss")
        
        for ($i = 0; $i -lt $lines.Length; $i++) {
            $line = $lines[$i]
            
            # Skip comments and empty lines
            if ([string]::IsNullOrWhiteSpace($line) -or $line.Trim().StartsWith('#')) {
                continue
            }
            
            # Check if this line contains the target IP
            if ($line -match "@$([regex]::Escape($IP))") {
                $parts = $line.Split(',')
                $url = $parts[0].Trim()
                
                # Use provided Generation or preserve existing
                $existingGeneration = if ($parts.Length -gt 3) { $parts[3] } else { $null }
                $generationToUse = if ($Generation) { $Generation } elseif ($existingGeneration) { $existingGeneration } else { $null }
                
                # Build updated line with all fields
                if ($generationToUse) {
                    # Include generation field (URL, Version, Timestamp, Generation)
                    $lines[$i] = "$url,$Version,$timestampStr,$generationToUse"
                    Write-Log -Message "[CACHE] Updated MS $IP`: Version=$Version, Gen=$generationToUse, Time=$timestampStr" -Level DEBUG
                } else {
                    # No generation field (URL, Version, Timestamp)
                    $lines[$i] = "$url,$Version,$timestampStr"
                    Write-Log -Message "[CACHE] Updated MS $IP`: Version=$Version, Time=$timestampStr (no generation)" -Level DEBUG
                }
                
                $updated = $true
                Write-Log -Message "Updated cache for MS $IP`: $Version ($timestampStr)" -Level DEBUG
                break
            }
        }
        
        if ($updated) {
            Set-Content -Path $FilePath -Value $lines -Encoding UTF8
        } else {
            Write-Warning "Could not find entry for MS $IP in $FilePath"
        }
        
    } catch {
        Write-Warning "Failed to update miniserver cache: $($_.Exception.Message)"
    }
}

function Get-MiniserverListWithCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Warning "Miniserver list file not found: $FilePath"
        return @()
    }
    
    Write-Log -Message "[CACHE] Reading miniserver list with cache from: $FilePath" -Level DEBUG
    
    $entries = @()
    $lines = Get-Content $FilePath
    $cacheHits = 0
    $totalEntries = 0
    
    foreach ($line in $lines) {
        $entry = ConvertFrom-MiniserverListEntry -Line $line
        if ($entry) {
            $totalEntries++
            if ($entry.CachedVersion -and $entry.CacheTimestamp) {
                $cacheHits++
                Write-Log -Message "[CACHE] Found cached entry for $($entry.IP): Version=$($entry.CachedVersion), Gen=$($entry.Generation), Timestamp=$($entry.CacheTimestamp)" -Level DEBUG
            }
            $entries += $entry
        }
    }
    
    Write-Log -Message "[CACHE] Loaded $totalEntries entries, $cacheHits with cache data" -Level INFO
    
    return $entries
}

Export-ModuleMember -Function ConvertFrom-MiniserverListEntry, Test-MiniserverCacheValid, Update-MiniserverListCache, Get-MiniserverListWithCache