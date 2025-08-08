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
    
    return $result
}

function Test-MiniserverCacheValid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $MSEntry,
        
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$TargetVersion,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxCacheAgeHours = 24
    )
    
    # No target version provided
    if ([string]::IsNullOrWhiteSpace($TargetVersion)) {
        return $false
    }
    
    # No cache available
    if (-not $MSEntry.HasCache -or -not $MSEntry.CachedVersion) {
        return $false
    }
    
    # Version mismatch
    if ($MSEntry.CachedVersion -ne $TargetVersion) {
        return $false
    }
    
    # Check cache age if timestamp available
    if ($MSEntry.LastChecked) {
        $ageHours = ((Get-Date) - $MSEntry.LastChecked).TotalHours
        if ($ageHours -gt $MaxCacheAgeHours) {
            Write-Log -Message "MS $($MSEntry.IP) cache expired (age: $([Math]::Round($ageHours, 1))h, max: ${MaxCacheAgeHours}h)" -Level DEBUG
            return $false
        }
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
                
                # Update with new version and timestamp
                $lines[$i] = "$url,$Version,$timestampStr"
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
    
    $entries = @()
    $lines = Get-Content $FilePath
    
    foreach ($line in $lines) {
        $entry = ConvertFrom-MiniserverListEntry -Line $line
        if ($entry) {
            $entries += $entry
        }
    }
    
    return $entries
}

Export-ModuleMember -Function ConvertFrom-MiniserverListEntry, Test-MiniserverCacheValid, Update-MiniserverListCache, Get-MiniserverListWithCache