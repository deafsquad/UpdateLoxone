# Simple test to verify mocks work correctly

# Create a simple test that uses mocks
Describe "Mock Infrastructure Test" {
    BeforeAll {
        # Load the module
        $modulePath = Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot)) "LoxoneUtils") "LoxoneUtils.psd1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
        }
        
        # Load mock for Network module
        . "$PSScriptRoot\LoxoneUtils.Network.TestMocks.ps1"
    }
    
    It "Should mock Invoke-LoxoneDownload without real download" {
        # Call the mocked function
        $testFile = Join-Path $env:TEMP "test-download.txt"
        $result = Invoke-LoxoneDownload -Url "http://test.com/file.zip" -DestinationPath $testFile -ActivityName "Test"
        
        # Verify mock worked
        $result.Succeeded | Should -Be $true
        $result.CalculatedCRC32 | Should -Be "MOCKCRC32"
        Test-Path $testFile | Should -Be $true
        
        # Clean up
        if (Test-Path $testFile) {
            Remove-Item $testFile -Force
        }
    }
    
    It "Should mock Get-InstalledVersion without real installation check" {
        # Load Installation mock
        . "$PSScriptRoot\LoxoneUtils.Installation.TestMocks.ps1"
        
        $version = Get-InstalledVersion -ExePath "C:\fake\path.exe"
        $version | Should -Be "14.0.0.0"
    }
    
    It "Should mock Miniserver operations" {
        # Load Miniserver mock
        . "$PSScriptRoot\LoxoneUtils.Miniserver.TestMocks.ps1"
        
        $version = Get-MiniserverVersion -URL "http://192.168.1.100"
        $version | Should -Be ([version]"14.0.0.0")
    }
}

# The test will be run when this script is invoked with Invoke-Pester
# Don't call Invoke-Pester from within the test file itself!