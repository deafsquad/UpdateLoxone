function Test-CoverageCompliance {
    <#
    .SYNOPSIS
        Validates test coverage compliance against established rules
    
    .DESCRIPTION
        Checks that all exported functions have corresponding test coverage
        and validates naming conventions. Can operate in different modes
        for gradual enforcement.
    
    .PARAMETER ChangedFunctions
        Only validate these specific functions (for new code validation)
        
    .PARAMETER StrictMode
        Enforce all rules without exceptions (for CI)
        
    .PARAMETER ExceptionFile
        Path to JSON file containing grandfathered exceptions
        
    .PARAMETER ShowViolations
        Display detailed violation information
        
    .EXAMPLE
        Test-CoverageCompliance -ShowViolations
        Validates all exported functions and shows violations
        
    .EXAMPLE
        Test-CoverageCompliance -ChangedFunctions @("Write-Log", "Get-Version") 
        Only validates specific functions (for pre-commit)
        
    .EXAMPLE
        Test-CoverageCompliance -StrictMode
        Full enforcement mode for CI pipeline
    #>
    [CmdletBinding()]
    param(
        [string[]]$ChangedFunctions = @(),
        [switch]$StrictMode,
        [string]$ExceptionFile = "TestCoverageExceptions.json",
        [switch]$ShowViolations
    )
    
    Write-Host "Testing Coverage Compliance..." -ForegroundColor Cyan
    
    # Get current coverage data using existing infrastructure
    $coverageData = Get-TestCoverage -IncludeTestResults:$false
    
    # Load exceptions if file exists
    $exceptions = @{
        grandfathered = @{}
        permanent = @{}
    }
    
    $exceptionPath = Join-Path (Split-Path $PSScriptRoot -Parent) $ExceptionFile
    if (Test-Path $exceptionPath) {
        try {
            $exceptions = ConvertFrom-JsonToHashtable -Json (Get-Content $exceptionPath -Raw)
        } catch {
            Write-Warning "Could not load exception file: $ExceptionFile"
        }
    }
    
    # Validation results
    $violations = @()
    $warnings = @()
    $compliantFunctions = 0
    $totalValidated = 0
    
    # Rule 1: Every exported function must have a test file
    foreach ($funcName in $coverageData.AllFunctions.Keys) {
        $func = $coverageData.AllFunctions[$funcName]
        
        # Only check exported functions
        if (-not $func.Exported) { continue }
        
        # If ChangedFunctions specified, only check those
        if ($ChangedFunctions.Count -gt 0 -and $funcName -notin $ChangedFunctions) {
            continue
        }
        
        $totalValidated++
        $moduleName = $func.Module
        
        # Check if function has exception
        $hasException = $false
        $exceptionReason = ""
        
        if ($exceptions.grandfathered.ContainsKey($funcName)) {
            $exception = $exceptions.grandfathered[$funcName]
            $expirationDate = [DateTime]::Parse($exception.expires)
            if ($expirationDate -gt (Get-Date)) {
                $hasException = $true
                $exceptionReason = "Grandfathered: $($exception.reason) (expires $($exception.expires))"
            } else {
                $warnings += "Expired exception for $funcName - was grandfathered until $($exception.expires)"
            }
        } elseif ($exceptions.permanent.ContainsKey($funcName)) {
            $hasException = $true
            $exceptionReason = "Permanent exception: $($exceptions.permanent[$funcName].reason)"
        }
        
        # Skip validation if has valid exception and not in strict mode
        if ($hasException -and -not $StrictMode) {
            if ($ShowViolations) {
                Write-Host "  âš ï¸  $funcName - $exceptionReason" -ForegroundColor Yellow
            }
            continue
        }
        
        # Validate test coverage
        $hasViolation = $false
        $violationDetails = @()
        
        # Check if function is tested
        if (-not $func.Tested) {
            $hasViolation = $true
            $violationDetails += "No test coverage found"
        }
        
        # Check test file naming convention
        $expectedTestFile = "$moduleName.Tests.ps1"
        $testFileExists = $false
        
        if ($func.TestDetails) {
            foreach ($detail in $func.TestDetails.Values) {
                $testFiles = $detail.TestFiles
                foreach ($testFile in $testFiles) {
                    if ($testFile -like "*$expectedTestFile") {
                        $testFileExists = $true
                        break
                    }
                }
                if ($testFileExists) { break }
            }
        }
        
        if (-not $testFileExists) {
            $hasViolation = $true
            $violationDetails += "Expected test file '$expectedTestFile' not found"
        }
        
        # Check Describe block naming convention
        if ($func.TestDetails) {
            $hasCorrectDescribe = $false
            foreach ($detail in $func.TestDetails.Values) {
                $expectedDescribe = "$funcName Function"
                if ($detail.Describe -eq $expectedDescribe -or $detail.Describe -like "*$funcName*") {
                    $hasCorrectDescribe = $true
                    break
                }
            }
            
            if (-not $hasCorrectDescribe) {
                $violationDetails += "Expected Describe block '$funcName Function' not found"
            }
        }
        
        # Record results
        if ($hasViolation) {
            $violations += @{
                Function = $funcName
                Module = $moduleName
                Details = $violationDetails
                HasException = $hasException
                ExceptionReason = $exceptionReason
            }
            
            if ($ShowViolations) {
                Write-Host "  âŒ $funcName [$moduleName]" -ForegroundColor Red
                foreach ($detail in $violationDetails) {
                    Write-Host "     - $detail" -ForegroundColor Red
                }
            }
        } else {
            $compliantFunctions++
            if ($ShowViolations) {
                Write-Host "  âœ… $funcName [$moduleName]" -ForegroundColor Green
            }
        }
    }
    
    # Summary
    $complianceRate = if ($totalValidated -gt 0) { 
        [math]::Round(($compliantFunctions / $totalValidated) * 100, 1) 
    } else { 100 }
    
    Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
    Write-Host "  Functions validated: $totalValidated"
    Write-Host "  Compliant: $compliantFunctions"
    Write-Host "  Violations: $($violations.Count)"
    Write-Host "  Warnings: $($warnings.Count)"
    Write-Host "  Compliance rate: $complianceRate%" -ForegroundColor $(if ($complianceRate -ge 90) { 'Green' } elseif ($complianceRate -ge 70) { 'Yellow' } else { 'Red' })
    
    if ($warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in $warnings) {
            Write-Host "  âš ï¸  $warning" -ForegroundColor Yellow
        }
    }
    
    # Return results
    $result = @{
        Compliant = ($violations.Count -eq 0)
        TotalValidated = $totalValidated
        CompliantFunctions = $compliantFunctions
        Violations = $violations
        Warnings = $warnings
        ComplianceRate = $complianceRate
    }
    
    if ($violations.Count -gt 0 -and $StrictMode) {
        throw "Coverage compliance failed: $($violations.Count) violations found"
    }
    
    return $result
}
