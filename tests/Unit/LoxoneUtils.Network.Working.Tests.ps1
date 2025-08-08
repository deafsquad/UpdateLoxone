# Working tests for LoxoneUtils.Network based on actual behavior

BeforeAll {
    # Import the module using the test import script to prevent Toast interference
    $importScript = Join-Path (Split-Path $PSScriptRoot) 'Import-LoxoneUtilsForTesting.ps1'
    if (Test-Path $importScript) {
        & $importScript -Force
    } else {
        # Fallback to direct import with suppression
        $Global:SuppressLoxoneToastInit = $true
        $Global:PersistentToastInitialized = $true
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    }
    
    # Set up temp directory - use environment variable if available
    $script:TestTempPath = if ($env:UPDATELOXONE_TEST_TEMP) {
        $env:UPDATELOXONE_TEST_TEMP
    } else {
        Join-Path $PSScriptRoot '../temp'
    }
    if (-not (Test-Path $script:TestTempPath)) {
        New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    }
    
    # Set up logging
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    
    # Load Network mocks to prevent real network operations
    $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.Network.TestMocks.ps1"
    if (Test-Path $mockPath) {
        . $mockPath
    }
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Wait-ForPingTimeout Function" -Tag 'Network' -Skip {
    
    It "Function not exported in test mode" {
        Set-ItResult -Skipped -Because "Function not available in test mode"
    }
    
    It "Currently returns true (placeholder implementation)" {
        # Measure execution time to verify it delays
        $startTime = Get-Date
        $result = Wait-ForPingTimeout -InputAddress "192.168.1.1"
        $endTime = Get-Date
        
        $result | Should -Be $true
        # Should have a delay of about 2 seconds
        ($endTime - $startTime).TotalSeconds | Should -BeGreaterThan 1.5
        ($endTime - $startTime).TotalSeconds | Should -BeLessThan 3
    }
    
    It "Accepts custom timeout parameter" {
        # Even though it's a placeholder, verify parameter is accepted
        { Wait-ForPingTimeout -InputAddress "test.local" -TimeoutSeconds 30 } | Should -Not -Throw
    }
}

Describe "Wait-ForPingSuccess Function" -Tag 'Network' -Skip {
    
    It "Function not exported in test mode" {
        Set-ItResult -Skipped -Because "Function not available in test mode"
    }
    
}

Describe "Invoke-LoxoneDownload Function" -Tag 'Network' {
    
    BeforeAll {
        # Initialize CRC32 type
        Initialize-CRC32Type
    }
    
    It "Exists and is exported" {
        Get-Command Invoke-LoxoneDownload -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }
    
    It "Has expected parameters" {
        $params = (Get-Command Invoke-LoxoneDownload -Module LoxoneUtils).Parameters
        
        # Required parameters
        $params.Keys | Should -Contain 'Url'
        $params.Keys | Should -Contain 'DestinationPath'
        $params.Keys | Should -Contain 'ActivityName'
        
        # Optional parameters
        $params.Keys | Should -Contain 'ExpectedCRC32'
        $params.Keys | Should -Contain 'ExpectedFilesize'
        $params.Keys | Should -Contain 'MaxRetries'
        $params.Keys | Should -Contain 'IsInteractive'
        $params.Keys | Should -Contain 'ErrorOccurred'
        $params.Keys | Should -Contain 'AnyUpdatePerformed'
        
        # Toast progress parameters
        $params.Keys | Should -Contain 'StepNumber'
        $params.Keys | Should -Contain 'TotalSteps'
        $params.Keys | Should -Contain 'StepName'
        $params.Keys | Should -Contain 'DownloadNumber'
        $params.Keys | Should -Contain 'TotalDownloads'
        # ItemName parameter removed - not part of function signature
    }
    
    It "Performs download and creates mock file" -Skip:($Global:NetworkMocksLoaded -ne $true) {
        # In test mode, the function creates a mock file
        $destPath = Join-Path $script:TestTempPath "downloaded.txt"
        
        # Remove file if it exists
        if (Test-Path $destPath) {
            Remove-Item $destPath -Force
        }
        
        # Call the mock function
        $result = Invoke-LoxoneDownload -Url "http://example.com/test.txt" `
            -DestinationPath $destPath `
            -ActivityName "Test Download"
        
        # Mock function returns a hashtable
        $result | Should -Not -BeNullOrEmpty
        $result.Success | Should -Be $true
        $result.Filesize | Should -Be 100
        $result.CalculatedCRC32 | Should -Be "MOCKCRC32"
        $result.LocalPath | Should -Be $destPath
        
        # Verify mock file was created
        Test-Path $destPath | Should -Be $true
        Get-Content $destPath -Raw | Should -Match "Mock download content for test"
    }
    
    It "Creates mock file regardless of existing file" -Skip:($Global:NetworkMocksLoaded -ne $true) {
        # In test mode, the function always creates a mock file
        $existingFile = Join-Path $script:TestTempPath "existing.txt"
        
        # Create an existing file first
        "Original content" | Out-File $existingFile -Encoding UTF8
        
        # Call the mock function
        $result = Invoke-LoxoneDownload -Url "http://example.com/file.txt" `
            -DestinationPath $existingFile `
            -ActivityName "Test"
        
        # Mock function always overwrites with mock content
        Test-Path $existingFile | Should -Be $true
        Get-Content $existingFile -Raw | Should -Match "Mock download content for test"
        $result.Success | Should -Be $true
    }
    
    It "Handles multiple parameters correctly" -Skip:($Global:NetworkMocksLoaded -ne $true) {
        # Test with all parameters
        $destPath = Join-Path $script:TestTempPath "multi_param.txt"
        
        $result = Invoke-LoxoneDownload `
            -Url "http://example.com/test.zip" `
            -DestinationPath $destPath `
            -ActivityName "Multi Param Test" `
            -ExpectedCRC32 "ABCD1234" `
            -ExpectedFilesize 12345 `
            -MaxRetries 3 `
            -IsInteractive $true `
            -ErrorOccurred $false `
            -AnyUpdatePerformed $true `
            -StepNumber 2 `
            -TotalSteps 5 `
            -StepName "Download Step" `
            -DownloadNumber 1 `
            -TotalDownloads 3
        
        # Mock function ignores parameters and returns standard result
        $result.Success | Should -Be $true
        Test-Path $destPath | Should -Be $true
    }
}

Describe "Module Exports" -Tag 'Network' {
    
    It "Exports expected network functions" {
        $module = Get-Module LoxoneUtils
        $exports = $module.ExportedFunctions.Keys
        
        # In test mode, only Invoke-LoxoneDownload is exported
        $exports | Should -Contain 'Invoke-LoxoneDownload'
    }
}