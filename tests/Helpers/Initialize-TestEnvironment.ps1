# Helper script to initialize test environment for modules that use logging functions

# Set test mode flags
$env:PESTER_TEST_RUN = "1"
$Global:IsTestRun = $true
$env:LOXONE_TEST_MODE = "1"

# Create global function overrides before any module loads
function global:Enter-Function {
    param($FunctionName, $FilePath, $LineNumber)
    # Track calls if needed but don't do actual logging
    if (-not $Global:TestEnterFunctionCalls) { $Global:TestEnterFunctionCalls = @() }
    $Global:TestEnterFunctionCalls += @{
        FunctionName = $FunctionName
        FilePath = $FilePath
        LineNumber = $LineNumber
        Time = Get-Date
    }
}

function global:Exit-Function {
    param($FunctionName, $ExitTime)
    # Track calls if needed but don't do actual logging
    if (-not $Global:TestExitFunctionCalls) { $Global:TestExitFunctionCalls = @() }
    $Global:TestExitFunctionCalls += @{
        FunctionName = $FunctionName
        ExitTime = $ExitTime
        Time = Get-Date
    }
}

function global:Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [switch]$SkipStackFrame
    )
    # Track calls if needed but don't do actual logging
    if (-not $Global:TestWriteLogCalls) { $Global:TestWriteLogCalls = @() }
    $Global:TestWriteLogCalls += @{
        Message = $Message
        Level = $Level
        SkipStackFrame = $SkipStackFrame
        Time = Get-Date
    }
}

# Initialize script-scoped variables that modules expect
if (-not $script:CallStack) {
    $script:CallStack = [System.Collections.Generic.Stack[object]]::new()
}

# Export a function to clean up after tests
function global:Clear-TestEnvironment {
    Remove-Item Function:\Enter-Function -ErrorAction SilentlyContinue
    Remove-Item Function:\Exit-Function -ErrorAction SilentlyContinue
    Remove-Item Function:\Write-Log -ErrorAction SilentlyContinue
    Remove-Variable -Name TestEnterFunctionCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name TestExitFunctionCalls -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name TestWriteLogCalls -Scope Global -ErrorAction SilentlyContinue
    $env:PESTER_TEST_RUN = $null
    $Global:IsTestRun = $null
    $env:LOXONE_TEST_MODE = $null
}

Write-Verbose "Test environment initialized with logging function overrides"