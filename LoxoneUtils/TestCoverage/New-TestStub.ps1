function New-TestStub {
    <#
    .SYNOPSIS
        Generates a test file template for a given function
    
    .DESCRIPTION
        Creates a properly structured Pester test file template with describe blocks,
        basic test cases, and proper naming conventions for the specified function.
    
    .PARAMETER FunctionName
        Name of the function to create a test for
        
    .PARAMETER ModuleName
        Name of the module containing the function (auto-detected if not specified)
        
    .PARAMETER OutputPath
        Path where the test file should be created (defaults to tests directory)
        
    .PARAMETER Force
        Overwrite existing test file if it exists
        
    .EXAMPLE
        New-TestStub -FunctionName "Write-Log"
        Creates a test file template for the Write-Log function
        
    .EXAMPLE
        New-TestStub -FunctionName "Get-Version" -ModuleName "LoxoneUtils.Utility" -Force
        Creates/overwrites test file for Get-Version function in specified module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,
        
        [string]$ModuleName,
        
        [string]$OutputPath,
        
        [switch]$Force
    )
    
    # Auto-detect module if not specified
    if (-not $ModuleName) {
        $coverageData = Get-TestCoverage -IncludeTestResults:$false
        $function = $coverageData.AllFunctions[$FunctionName]
        if ($function) {
            $ModuleName = $function.Module
        } else {
            throw "Function '$FunctionName' not found in any module"
        }
    }
    
    # Set default output path
    if (-not $OutputPath) {
        $OutputPath = Join-Path $script:TestPath "$ModuleName.Tests.ps1"
    }
    
    # Check if file exists
    if ((Test-Path $OutputPath) -and -not $Force) {
        throw "Test file already exists at '$OutputPath'. Use -Force to overwrite."
    }
    
    # Generate test template
    $template = @"
#Requires -Version 5.0

BeforeAll {
    # Import the module
    Import-Module `$PSScriptRoot\..\LoxoneUtils\LoxoneUtils.psd1 -Force
}
