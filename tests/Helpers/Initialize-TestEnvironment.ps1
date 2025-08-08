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

# Load toast notification mocks to prevent real notifications
# But skip this if we're in LiveProgress mode (which needs real notifications)
if (-not $env:LOXONE_LIVEPROGRESS_MODE) {
    $toastMocksPath = Join-Path (Split-Path $PSScriptRoot) "Helpers\Mock-ToastNotifications.ps1"
    if (Test-Path $toastMocksPath) {
        . $toastMocksPath
    }
}

# Initialize script-scoped variables that modules expect
if (-not $script:CallStack) {
    $script:CallStack = [System.Collections.Generic.Stack[object]]::new()
}

# Load the module mocking helper
. (Join-Path $PSScriptRoot 'Initialize-ModuleMocks.ps1')

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

# Ensure functions are available in module scopes
# This is needed because modules may not have imported LoxoneUtils.Logging yet
$modules = @(
    'LoxoneUtils.Installation',
    'LoxoneUtils.Network', 
    'LoxoneUtils.Miniserver',
    'LoxoneUtils.System',
    'LoxoneUtils.UpdateCheck',
    'LoxoneUtils.Utility',
    'LoxoneUtils.WorkflowSteps',
    'LoxoneUtils.Toast',
    'LoxoneUtils.RunAsUser',
    'LoxoneUtils.ErrorHandling'
)

foreach ($moduleName in $modules) {
    # Check if module is already loaded
    $module = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
    if ($module) {
        # Inject the functions into the module's scope
        & $module {
            if (-not (Get-Command Enter-Function -ErrorAction SilentlyContinue)) {
                function Enter-Function {
                    param($FunctionName, $FilePath, $LineNumber)
                    # No-op in test mode
                }
            }
            if (-not (Get-Command Exit-Function -ErrorAction SilentlyContinue)) {
                function Exit-Function {
                    param($FunctionName, $ExitTime)
                    # No-op in test mode
                }
            }
            if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
                function Write-Log {
                    param(
                        [string]$Message,
                        [string]$Level = 'INFO',
                        [switch]$SkipStackFrame
                    )
                    # Write to console in test mode if verbose
                    if ($VerbosePreference -eq 'Continue') {
                        Write-Verbose "[TEST-LOG] [$Level] $Message"
                    }
                }
            }
        }
    }
}

Write-Verbose "Test environment initialized with logging function overrides"