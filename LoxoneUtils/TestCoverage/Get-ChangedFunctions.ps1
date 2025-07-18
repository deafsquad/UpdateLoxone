function Get-ChangedFunctions {
    <#
    .SYNOPSIS
        Gets list of functions that have been modified in git working tree
    
    .DESCRIPTION
        Uses git diff to identify functions that have been added or modified
        since the last commit, enabling new-code-only validation.
    
    .PARAMETER CompareWith
        Git reference to compare with (default: HEAD)
        
    .PARAMETER IncludeStaged
        Include staged changes in analysis
        
    .PARAMETER ModulePath
        Path to the module directory (default: auto-detected)
        
    .EXAMPLE
        Get-ChangedFunctions
        Gets functions modified in working directory since last commit
        
    .EXAMPLE
        Get-ChangedFunctions -CompareWith "main"
        Gets functions modified since main branch
        
    .EXAMPLE
        Get-ChangedFunctions -IncludeStaged
        Includes both staged and unstaged changes
    #>
    [CmdletBinding()]
    param(
        [string]$CompareWith = "HEAD",
        
        [switch]$IncludeStaged,
        
        [string]$ModulePath
    )
    
    Write-Host "Analyzing changed functions..." -ForegroundColor Cyan
    
    # Set default module path
    if (-not $ModulePath) {
        $ModulePath = Join-Path $script:ModulePath 'LoxoneUtils'
    }
    
    $changedFunctions = @()
    
    try {
        # Get git diff for PowerShell module files
        $diffArgs = @("diff")
        if ($IncludeStaged) {
            $diffArgs += "--cached"
        }
        $diffArgs += @("$CompareWith", "--name-only", "--", "$ModulePath/*.psm1")
        
        $changedFiles = & git @diffArgs 2>$null
        
        if (-not $changedFiles) {
            Write-Host "No changed PowerShell module files found" -ForegroundColor Gray
            return @()
        }
        
        Write-Host "Changed files: $($changedFiles.Count)" -ForegroundColor Yellow
        
        # For each changed file, get the detailed diff to identify changed functions
        foreach ($file in $changedFiles) {
            Write-Host "  Analyzing: $file" -ForegroundColor Gray
            
            # Get detailed diff for the file
            $detailDiffArgs = @("diff")
            if ($IncludeStaged) {
                $detailDiffArgs += "--cached"
            }
            $detailDiffArgs += @("$CompareWith", "--", $file)
            
            $diff = & git @detailDiffArgs 2>$null
            
            if ($diff) {
                # Parse diff to find function changes
                $functionPattern = '^\+.*function\s+([A-Z][\w-]+)'
                $modifiedFunctionPattern = '^\@@.*\+\d+,\d+.*\@@.*([A-Z][\w-]+)'
                
                foreach ($line in $diff) {
                    # New functions (lines starting with +)
                    if ($line -match $functionPattern) {
                        $funcName = $matches[1]
                        if ($funcName -notin $changedFunctions) {
                            $changedFunctions += $funcName
                            Write-Host "    Found new function: $funcName" -ForegroundColor Green
                        }
                    }
                    # Modified function contexts (hunk headers)
                    elseif ($line -match $modifiedFunctionPattern) {
                        $funcName = $matches[1]
                        if ($funcName -notin $changedFunctions) {
                            $changedFunctions += $funcName
                            Write-Host "    Found modified context: $funcName" -ForegroundColor Yellow
                        }
                    }
                }
            }
        }
        
        # Also check for completely new functions in working directory vs current coverage
        Write-Host "  Cross-checking with current function list..." -ForegroundColor Gray
        $currentCoverage = Get-TestCoverage -IncludeTestResults:$false
        
        # Get functions from the current files that might be new
        foreach ($file in $changedFiles) {
            if (Test-Path $file) {
                $content = Get-Content $file -Raw
                $functionMatches = [regex]::Matches($content, 'function\s+([A-Z][\w-]+)')
                
                foreach ($match in $functionMatches) {
                    $funcName = $match.Groups[1].Value
                    
                    # If function exists in current coverage but wasn't in git diff,
                    # it might be a newly added function
                    if ($funcName -notin $changedFunctions -and 
                        $currentCoverage.AllFunctions.ContainsKey($funcName)) {
                        
                        # Check if this might be a recent addition by checking git log
                        $logResult = & git log --oneline -1 --grep="$funcName" 2>$null
                        if ($logResult -or (& git log --oneline -5 --name-only | Select-String -Pattern $file)) {
                            $changedFunctions += $funcName
                            Write-Host "    Found potentially new function: $funcName" -ForegroundColor Cyan
                        }
                    }
                }
            }
        }
        
    } catch {
        Write-Warning "Git analysis failed: $($_.Exception.Message)"
        Write-Host "Falling back to manual change detection..." -ForegroundColor Yellow
        
        # Fallback: assume all untested functions are "changed"
        $coverage = Get-TestCoverage -IncludeTestResults:$false
        $changedFunctions = $coverage.AllFunctions.Keys | Where-Object {
            $func = $coverage.AllFunctions[$_]
            $func.Exported -and -not $func.Tested
        }
        
        Write-Host "Fallback detected $($changedFunctions.Count) untested functions as changed" -ForegroundColor Yellow
    }
    
    Write-Host "Total changed functions identified: $($changedFunctions.Count)" -ForegroundColor White
    
    return $changedFunctions
}
