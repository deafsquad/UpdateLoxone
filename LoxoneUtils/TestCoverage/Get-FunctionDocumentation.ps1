function Get-FunctionDocumentation {
    param(
        [string]$FunctionName,
        [string]$FileContent
    )
    
    # Debug output - this should appear for every function
    Write-Verbose "Get-FunctionDocumentation called for: $FunctionName" -Verbose
    
    # Known problematic functions - return immediately with SIMPLE VALUES
    if ($FunctionName -in @('Get-InstalledVersion', 'Start-LoxoneUpdateInstaller', 'Invoke-LoxoneDownload', 'Enter-Function', 'Exit-Function')) {
        Write-Verbose "Skipping problematic function: $FunctionName" -Verbose
        # Return simple string values to avoid PowerShell object evaluation issues
        return [PSCustomObject]@{
            Synopsis = "Skipped"
            Description = "N/A"
            Parameters = "None"
            Examples = "None"
            HasDocumentation = "No"
            CompletionScore = "0"
        }
    }
    
    # ALWAYS use simple mode to prevent hanging - the complex regex is too dangerous
    # Check for test mode and return minimal result to avoid regex hanging
    if ($env:PESTER_TEST_RUN -eq "1" -or $Global:IsTestRun -eq $true -or $env:LOXONE_TEST_MODE -eq "1" -or $true) {
        # Ultra-simple check that avoids complex regex entirely
        $hasBasicDoc = ($FileContent.Contains("<#") -and $FileContent.Contains(".SYNOPSIS") -and $FileContent.Contains("#>"))
        
        # Try to extract simple synopsis if it exists
        $synopsis = ""
        if ($hasBasicDoc) {
            try {
                # Very simple synopsis extraction without regex - with timeout protection
                $lines = $FileContent -split "`n"
                $synopsisFound = $false
                $lineCount = 0
                foreach ($line in $lines) {
                    $lineCount++
                    # Safety: stop after 1000 lines to prevent infinite loops
                    if ($lineCount -gt 1000) { break }
                    
                    if ($line.Contains(".SYNOPSIS")) {
                        $synopsisFound = $true
                        continue
                    }
                    if ($synopsisFound -and $line.Trim() -and -not $line.Trim().StartsWith(".")) {
                        $synopsis = $line.Trim()
                        if ($synopsis.Length -gt 200) {
                            $synopsis = $synopsis.Substring(0, 200) + "..."
                        }
                        break
                    }
                }
            }
            catch {
                # If anything fails, just skip synopsis extraction
                $synopsis = "Error extracting synopsis"
            }
        }
        
        # Return simple string values to avoid PowerShell object evaluation issues
        return [PSCustomObject]@{
            Synopsis = if ($synopsis) { $synopsis } else { "" }
            Description = ""
            Parameters = "None"
            Examples = "None"
            HasDocumentation = if ($hasBasicDoc) { "Yes" } else { "No" }
            CompletionScore = if ($hasBasicDoc) { "50" } else { "0" }
        }
    }
    
    # Use PSCustomObject with simple string values
    $docInfo = [PSCustomObject]@{
        Synopsis = ""
        Description = ""
        Parameters = "None"
        Examples = "None"
        HasDocumentation = "No"
        CompletionScore = "0"
    }
    
    # Safer, simpler approach: find the comment block first, then extract parts
    try {
        # Look for comment block before the function (with timeout protection)
        $lines = $FileContent -split "`n"
        $funcLineIndex = -1
        
        # Find the function line
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "^\s*function\s+$FunctionName\s*\{") {
                $funcLineIndex = $i
                break
            }
        }
        
        if ($funcLineIndex -gt 0) {
            # Look backwards for comment block
            $commentStart = -1
            $commentEnd = -1
            
            for ($i = $funcLineIndex - 1; $i -ge 0; $i--) {
                if ($lines[$i] -match "#>") {
                    $commentEnd = $i
                } elseif ($lines[$i] -match "<#" -and $commentEnd -gt -1) {
                    $commentStart = $i
                    break
                }
                # Stop looking after 50 lines to prevent infinite loops
                if (($funcLineIndex - $i) -gt 50) { break }
            }
            
            if ($commentStart -ge 0 -and $commentEnd -gt $commentStart) {
                $helpBlock = ($lines[$commentStart..$commentEnd] -join "`n")
                $docInfo.HasDocumentation = "Yes"
                
                # Simple extraction without complex regex
                $score = 0
                if ($helpBlock -match '\.SYNOPSIS[^.]*?([^.]+)') {
                    $docInfo.Synopsis = $matches[1].Trim()
                    $score += 25
                }
                
                if ($helpBlock -match '\.DESCRIPTION') {
                    $score += 25
                }
                
                if ($helpBlock -match '\.PARAMETER') {
                    $score += 25
                }
                
                if ($helpBlock -match '\.EXAMPLE') {
                    $score += 25
                }
                
                $docInfo.CompletionScore = $score.ToString()
            }
        }
    } catch {
        # If anything fails, just return basic info
        Write-Verbose "Error parsing documentation for ${FunctionName}: $_"
    }
    
    return $docInfo
}
