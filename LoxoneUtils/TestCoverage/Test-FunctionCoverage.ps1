function Test-FunctionCoverage {
    <#
    .SYNOPSIS
        Checks test coverage compliance for a specific function
    
    .DESCRIPTION
        Validates that a specific function has proper test coverage and meets
        all naming conventions and compliance rules.
    
    .PARAMETER FunctionName
        Name of the function to check
        
    .PARAMETER ShowDetails
        Show detailed compliance information
        
    .EXAMPLE
        Test-FunctionCoverage -FunctionName "Write-Log"
        Checks if Write-Log function has proper test coverage
        
    .EXAMPLE
        Test-FunctionCoverage -FunctionName "Get-Version" -ShowDetails
        Shows detailed compliance information for Get-Version function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,
        
        [switch]$ShowDetails
    )
    
    Write-Host "Checking coverage for function: $FunctionName" -ForegroundColor Cyan
    
    # Get coverage data
    $coverageData = Get-TestCoverage -IncludeTestResults:$false
    
    # Check if function exists
    if (-not $coverageData.AllFunctions.ContainsKey($FunctionName)) {
        Write-Host "âŒ Function '$FunctionName' not found in any module" -ForegroundColor Red
        return $false
    }
    
    $function = $coverageData.AllFunctions[$FunctionName]
    $isCompliant = $true
    $issues = @()
    
    # Check 1: Is function exported?
    if (-not $function.Exported) {
        Write-Host "â„¹ï¸  Function '$FunctionName' is internal - compliance not required" -ForegroundColor Blue
        return $true
    }
    
    # Check 2: Has test coverage?
    if (-not $function.Tested) {
        $issues += "No test coverage found"
        $isCompliant = $false
    }
    
    # Check 3: Test file naming convention
    $expectedTestFile = "$($function.Module).Tests.ps1"
    $testPath = Join-Path $script:TestPath $expectedTestFile
    if (-not (Test-Path $testPath)) {
        $issues += "Expected test file not found: $expectedTestFile"
        $isCompliant = $false
    }
    
    # Check 4: Test structure (if test exists)
    if ($function.Tested -and (Test-Path $testPath)) {
        $testContent = Get-Content $testPath -Raw
        $expectedDescribe = "Describe `"$FunctionName Function`""
        if ($testContent -notmatch [regex]::Escape($expectedDescribe)) {
            $issues += "Test file does not contain expected Describe block: '$expectedDescribe'"
            $isCompliant = $false
        }
    }
    
    # Check 5: Exception status
    $exceptionPath = Join-Path (Split-Path $script:ModulePath -Parent) "TestCoverageExceptions.json"
    $hasException = $false
    if (Test-Path $exceptionPath) {
        try {
            $exceptions = ConvertFrom-JsonToHashtable -Json (Get-Content $exceptionPath -Raw)
            if ($exceptions.grandfathered.ContainsKey($FunctionName) -or $exceptions.permanent.ContainsKey($FunctionName)) {
                $hasException = $true
            }
        } catch {
            # Ignore exception file errors
        }
    }
    
    # Report results
    if ($isCompliant) {
        Write-Host "âœ… Function '$FunctionName' is compliant" -ForegroundColor Green
    } elseif ($hasException) {
        Write-Host "âš ï¸  Function '$FunctionName' has violations but is exempted" -ForegroundColor Yellow
    } else {
        Write-Host "âŒ Function '$FunctionName' is not compliant" -ForegroundColor Red
    }
    
    if ($ShowDetails -or -not $isCompliant) {
        Write-Host "`nDetails:" -ForegroundColor White
        Write-Host "  Module: $($function.Module)" -ForegroundColor Gray
        Write-Host "  Exported: $($function.Exported)" -ForegroundColor Gray
        Write-Host "  Tested: $($function.Tested)" -ForegroundColor Gray
        Write-Host "  Test Count: $($function.TestCount)" -ForegroundColor Gray
        if ($hasException) {
            Write-Host "  Exception: Yes (check TestCoverageExceptions.json)" -ForegroundColor Yellow
        }
        
        if ($issues.Count -gt 0) {
            Write-Host "  Issues:" -ForegroundColor Red
            foreach ($issue in $issues) {
                Write-Host "    - $issue" -ForegroundColor Red
            }
        }
        
        if ($function.TestDetails.Count -gt 0) {
            Write-Host "  Test Details:" -ForegroundColor Gray
            foreach ($test in $function.TestDetails.Keys) {
                Write-Host "    - $test" -ForegroundColor Gray
            }
        }
    }
    
    return $isCompliant
}
