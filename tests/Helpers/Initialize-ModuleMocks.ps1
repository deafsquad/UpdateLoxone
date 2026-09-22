# Helper to initialize mocks for logging functions in all LoxoneUtils modules
# This should be called in BeforeAll blocks after importing the main module

function Initialize-ModuleMocks {
    [CmdletBinding()]
    param(
        [string[]]$ModuleNames = @(
            'LoxoneUtils.Installation',
            'LoxoneUtils.Network',
            'LoxoneUtils.Miniserver',
            'LoxoneUtils.System',
            'LoxoneUtils.UpdateCheck',
            'LoxoneUtils.Utility',
            'LoxoneUtils.WorkflowSteps',
            'LoxoneUtils.Toast',
            'LoxoneUtils.RunAsUser',
            'LoxoneUtils.ErrorHandling',
            'LoxoneUtils.ParallelWorkflow',
            'LoxoneUtils.ConsoleProgress',
            'LoxoneUtils.ThreadSafe'
        )
    )
    
    Write-Verbose "Initializing module mocks for: $($ModuleNames -join ', ')"
    
    # First, ensure the main LoxoneUtils module is loaded with its nested modules
    if (-not (Get-Module LoxoneUtils)) {
        $modulePath = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -Global
        }
    }
    
    # Mock in the parent module first
    if (Get-Module LoxoneUtils) {
        Write-Verbose "Mocking logging functions in parent module: LoxoneUtils"
        Mock Enter-Function {} -ModuleName LoxoneUtils
        Mock Exit-Function {} -ModuleName LoxoneUtils  
        Mock Write-Log {} -ModuleName LoxoneUtils
    }
    
    foreach ($moduleName in $ModuleNames) {
        # Check if module is loaded
        $module = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
        
        if ($module) {
            Write-Verbose "Mocking logging functions in module: $moduleName"
            
            # Always mock, don't check if already exists - Pester will handle duplicates
            try {
                Mock Enter-Function {} -ModuleName $moduleName -ErrorAction SilentlyContinue
                Mock Exit-Function {} -ModuleName $moduleName -ErrorAction SilentlyContinue
                Mock Write-Log {
                    param(
                        [string]$Message,
                        [string]$Level = 'INFO',
                        [switch]$SkipStackFrame
                    )
                    # In test mode, optionally write to verbose stream
                    if ($VerbosePreference -eq 'Continue' -or $env:LOXONE_TEST_VERBOSE -eq '1') {
                        Write-Verbose "[MOCK-LOG] [$Level] $Message"
                    }
                } -ModuleName $moduleName -ErrorAction SilentlyContinue
            } catch {
                Write-Verbose "Could not mock in $moduleName : $_"
            }
        } else {
            Write-Verbose "Module $moduleName not loaded, skipping mock setup"
        }
    }
}

# Function is now available in global scope