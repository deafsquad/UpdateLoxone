function Test-NewCodeCompliance {
    <#
    .SYNOPSIS
        Validates test coverage compliance only for new or modified code
    
    .DESCRIPTION
        Implements new-code-only validation by checking compliance only for
        functions that have been modified since a specified git reference.
        This allows gradual enforcement without breaking existing workflows.
    
    .PARAMETER CompareWith
        Git reference to compare with (default: HEAD)
        
    .PARAMETER IncludeStaged
        Include staged changes in analysis
        
    .PARAMETER StrictMode
        Fail if any new code violations are found
        
    .PARAMETER ShowViolations
        Display detailed violation information
        
    .PARAMETER ExceptionFile
        Path to exception file (default: TestCoverageExceptions.json)
        
    .EXAMPLE
        Test-NewCodeCompliance
        Validates compliance for functions modified since last commit
        
    .EXAMPLE
        Test-NewCodeCompliance -CompareWith "main" -StrictMode
        Strict validation against main branch (for CI)
        
    .EXAMPLE
        Test-NewCodeCompliance -ShowViolations
        Shows detailed information about any new violations
    #>
    [CmdletBinding()]
    param(
        [string]$CompareWith = "HEAD",
        
        [switch]$IncludeStaged,
        
        [switch]$StrictMode,
        
        [switch]$ShowViolations,
        
        [string]$ExceptionFile = "TestCoverageExceptions.json"
    )
    
    Write-Host "Testing New Code Compliance..." -ForegroundColor Cyan
    Write-Host "Comparing with: $CompareWith" -ForegroundColor Gray
    
    # Get list of changed functions
    $changedFunctions = Get-ChangedFunctions -CompareWith $CompareWith -IncludeStaged:$IncludeStaged
    
    if ($changedFunctions.Count -eq 0) {
        Write-Host "âœ… No function changes detected - compliance check passed" -ForegroundColor Green
        return @{
            Passed = $true
            ChangedFunctions = @()
            Violations = @()
            Message = "No changes detected"
        }
    }
    
    Write-Host "Validating $($changedFunctions.Count) changed functions..." -ForegroundColor Yellow
    
    # Run compliance check only on changed functions
    $complianceResult = Test-CoverageCompliance -ChangedFunctions $changedFunctions -ExceptionFile $ExceptionFile -ShowViolations:$ShowViolations
    
    # Analyze results for new code
    $newViolations = @()
    if ($complianceResult.Violations.Count -gt 0) {
        foreach ($violation in $complianceResult.Violations) {
            if ($violation.FunctionName -in $changedFunctions) {
                $newViolations += $violation
            }
        }
    }
    
    $passed = $newViolations.Count -eq 0
    
    # Report results
    Write-Host "`nNew Code Compliance Results:" -ForegroundColor White
    Write-Host "============================" -ForegroundColor White
    Write-Host "Changed functions analyzed: $($changedFunctions.Count)" -ForegroundColor Gray
    Write-Host "New violations found: $($newViolations.Count)" -ForegroundColor $(if ($newViolations.Count -eq 0) { "Green" } else { "Red" })
    
    if ($newViolations.Count -gt 0) {
        Write-Host "`nNew violations:" -ForegroundColor Red
        foreach ($violation in $newViolations) {
            Write-Host "  âŒ $($violation.FunctionName) ($($violation.Module))" -ForegroundColor Red
            if ($violation.Issues) {
                foreach ($issue in $violation.Issues) {
                    Write-Host "     - $issue" -ForegroundColor Yellow
                }
            }
        }
        
        Write-Host "`nðŸ’¡ Fix these violations by:" -ForegroundColor Cyan
        Write-Host "   1. Running: New-TestStub -FunctionName 'YourFunction'" -ForegroundColor Gray
        Write-Host "   2. Writing proper test cases" -ForegroundColor Gray
        Write-Host "   3. Adding exceptions to $ExceptionFile if justified" -ForegroundColor Gray
        
        if ($StrictMode) {
            throw "New code compliance failed: $($newViolations.Count) violations found"
        }
    } else {
        Write-Host "âœ… All new code complies with testing requirements!" -ForegroundColor Green
    }
    
    return @{
        Passed = $passed
        ChangedFunctions = $changedFunctions
        Violations = $newViolations
        TotalChecked = $changedFunctions.Count
        ComplianceRate = if ($changedFunctions.Count -gt 0) { 
            [math]::Round((($changedFunctions.Count - $newViolations.Count) / $changedFunctions.Count) * 100, 1) 
        } else { 100 }
        Message = if ($passed) { "All new code compliant" } else { "$($newViolations.Count) new violations found" }
    }
}
