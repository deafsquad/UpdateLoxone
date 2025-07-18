function Get-ComplianceViolations {
    <#
    .SYNOPSIS
        Gets a list of compliance violations for a specific module or all modules
    
    .DESCRIPTION
        Analyzes test coverage compliance and returns detailed violation information
        for troubleshooting and planning purposes.
    
    .PARAMETER ModuleName
        Specific module to analyze (analyzes all modules if not specified)
        
    .PARAMETER IncludeExempted
        Include functions that have exceptions in the results
        
    .EXAMPLE
        Get-ComplianceViolations
        Gets all compliance violations across all modules
        
    .EXAMPLE
        Get-ComplianceViolations -ModuleName "LoxoneUtils.TestTracking"
        Gets violations for a specific module
        
    .EXAMPLE
        Get-ComplianceViolations -IncludeExempted
        Includes exempted functions in the violation report
    #>
    [CmdletBinding()]
    param(
        [string]$ModuleName,
        
        [switch]$IncludeExempted
    )
    
    Write-Host "Analyzing compliance violations..." -ForegroundColor Cyan
    
    # Get coverage data
    $coverageData = Get-TestCoverage -IncludeTestResults:$false
    
    # Load exceptions
    $exceptions = @{ grandfathered = @{}; permanent = @{} }
    $exceptionPath = Join-Path (Split-Path $script:ModulePath -Parent) "TestCoverageExceptions.json"
    if (Test-Path $exceptionPath) {
        try {
            $exceptions = ConvertFrom-JsonToHashtable -Json (Get-Content $exceptionPath -Raw)
        } catch {
            Write-Warning "Could not load exception file: $exceptionPath"
        }
    }
    
    $violations = @()
    
    foreach ($funcName in $coverageData.AllFunctions.Keys) {
        $function = $coverageData.AllFunctions[$funcName]
        
        # Only check exported functions
        if (-not $function.Exported) { continue }
        
        # Filter by module if specified
        if ($ModuleName -and $function.Module -ne $ModuleName) { continue }
        
        # Check for violations
        $hasViolation = -not $function.Tested
        
        # Check exception status
        $hasException = $exceptions.grandfathered.ContainsKey($funcName) -or $exceptions.permanent.ContainsKey($funcName)
        
        # Include based on parameters
        if ($hasViolation -and (-not $hasException -or $IncludeExempted)) {
            $violations += [PSCustomObject]@{
                FunctionName = $funcName
                Module = $function.Module
                Tested = $function.Tested
                TestCount = $function.TestCount
                HasException = $hasException
                ExceptionType = if ($exceptions.grandfathered.ContainsKey($funcName)) { "Grandfathered" } 
                               elseif ($exceptions.permanent.ContainsKey($funcName)) { "Permanent" } 
                               else { "None" }
                ExceptionReason = if ($exceptions.grandfathered.ContainsKey($funcName)) { $exceptions.grandfathered[$funcName].reason }
                                 elseif ($exceptions.permanent.ContainsKey($funcName)) { $exceptions.permanent[$funcName].reason }
                                 else { "" }
                Priority = if ($function.Module -like "*TestTracking*") { "Low (Experimental)" }
                          elseif ($function.Module -like "*TestCoverage*") { "Low (Meta)" }
                          elseif ($function.Module -like "*Utility*") { "Medium" }
                          else { "High" }
            }
        }
    }
    
    # Sort by priority and module
    $violations = $violations | Sort-Object Priority, Module, FunctionName
    
    # Display summary
    Write-Host "`nCompliance Violations Summary:" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Yellow
    Write-Host "Total violations: $($violations.Count)" -ForegroundColor White
    
    if ($violations.Count -gt 0) {
        $violationsByModule = $violations | Group-Object Module
        foreach ($group in $violationsByModule) {
            $exempted = ($group.Group | Where-Object HasException).Count
            $active = $group.Count - $exempted
            Write-Host "  $($group.Name): $($group.Count) total ($active active, $exempted exempted)" -ForegroundColor Gray
        }
        
        Write-Host "`nDetailed Violations:" -ForegroundColor White
        $violations | Format-Table FunctionName, Module, Priority, ExceptionType, ExceptionReason -AutoSize
    }
    
    return $violations
}
