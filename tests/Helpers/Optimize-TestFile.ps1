# Template for optimized BeforeAll block in test files
# This avoids reloading the module if it's already loaded

$OptimizedBeforeAll = @'
BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
    
    # Your test-specific setup here...
}
'@

Write-Host @"
To optimize test file performance, replace the BeforeAll block with:

$OptimizedBeforeAll

Key improvements:
1. Checks if module is already loaded globally
2. Avoids Force reload if not needed  
3. Reduces module import from 39+ times to 1 time
4. Can reduce test execution time by 30-50%
"@