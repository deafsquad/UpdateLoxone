# Toast Test Optimization - Prevents mutex creation in tests
# This file should be dot-sourced in toast test files BEFORE importing the module

# Create a fake mutex class that doesn't block
if (-not ([System.Management.Automation.PSTypeName]'MockMutex').Type) {
    Add-Type -TypeDefinition @'
    public class MockMutex {
        public bool WaitOne(int timeout) { return true; }
        public void ReleaseMutex() { }
        public void Dispose() { }
    }
'@
}

# Override New-Object to return our mock for mutex creation
$Global:OriginalNewObject = Get-Command New-Object -CommandType Cmdlet
function Global:New-Object {
    param(
        [Parameter(Position=0)]$TypeName,
        [Parameter(Position=1)]$ArgumentList
    )
    
    if ($TypeName -eq 'System.Threading.Mutex') {
        # Return our non-blocking mock
        return [MockMutex]::new()
    }
    
    # Call original for everything else
    & $Global:OriginalNewObject @PSBoundParameters
}

# Set all suppression flags
$Global:SuppressLoxoneToastInit = $true
$Global:NoToastMutex = $true
$env:LOXONE_DISABLE_TOAST_MUTEX = "1"
$env:PESTER_TEST_RUN = "1"

Write-Host "Toast mutex bypass activated for tests" -ForegroundColor Green