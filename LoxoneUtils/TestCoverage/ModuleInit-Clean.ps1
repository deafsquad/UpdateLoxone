#Requires -Version 5.0
<#
.SYNOPSIS
    Test coverage analysis module for UpdateLoxone

.DESCRIPTION
    Provides comprehensive test coverage analysis functionality including:
    - Function discovery across all modules
    - Test coverage calculation
    - Report generation with summary and details
    - Deprecated test reference tracking
    - Function usage analysis
#>

# Module variables
$script:ModulePath = if ($PSScriptRoot) { 
    Split-Path $PSScriptRoot -Parent 
} else { 
    # Fallback when PSScriptRoot is not available (e.g., in certain admin contexts)
    $moduleFile = (Get-Module LoxoneUtils).Path
    if ($moduleFile) {
        Split-Path (Split-Path $moduleFile -Parent) -Parent
    } else {
        # Ultimate fallback - use current location
        Get-Location
    }
}
$script:TestPath = Join-Path $script:ModulePath 'tests'

# Balance braces - module scope fix
if ($false) { }
if ($false) { }

# Export module functions
Export-ModuleMember -Function @(
    'Get-TestCoverage',
    'New-TestCoverageReport',
    'Get-TestResults',
    'Test-CoverageCompliance',
    'New-TestStub',
    'Test-FunctionCoverage',
    'Get-ComplianceViolations',
    'Get-ChangedFunctions',
    'Test-NewCodeCompliance'
)