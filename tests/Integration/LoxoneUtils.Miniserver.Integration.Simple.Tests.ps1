# Simplified integration tests for Miniserver functions
# These should complete quickly even with network issues

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Remove-Module LoxoneUtils -Force -ErrorAction SilentlyContinue
    
    # Disable test mode for integration tests
    $script:OriginalTestMode = $env:PESTER_TEST_RUN
    $script:OriginalLoxoneTestMode = $env:LOXONE_TEST_MODE
    $script:OriginalIsTestRun = $Global:IsTestRun
    $env:PESTER_TEST_RUN = "0"
    $env:LOXONE_TEST_MODE = "0"
    $Global:IsTestRun = $false
    
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Mock Update-PersistentToast to avoid UI
    Mock Update-PersistentToast {} -ModuleName LoxoneUtils
}

AfterAll {
    # Restore test mode settings
    if ($null -ne $script:OriginalTestMode) {
        $env:PESTER_TEST_RUN = $script:OriginalTestMode
    }
    if ($null -ne $script:OriginalLoxoneTestMode) {
        $env:LOXONE_TEST_MODE = $script:OriginalLoxoneTestMode
    }
    if ($null -ne $script:OriginalIsTestRun) {
        $Global:IsTestRun = $script:OriginalIsTestRun
    }
}

Describe "Miniserver Integration - Quick Tests" -Tag 'Integration' {
    
    It "Get-MiniserverVersion handles invalid URLs gracefully" {
        # This should fail quickly without hanging
        $result = Get-MiniserverVersion -MSEntry "http://invalid.test.local" -TimeoutSec 1
        
        $result | Should -Not -BeNullOrEmpty
        $result.Error | Should -Not -BeNullOrEmpty
        $result.MSIP | Should -Be "invalid.test.local"
    }
    
    It "Update-MS processes empty list without errors" {
        # Use test isolation temp path
        $tempPath = if ($env:UPDATELOXONE_TEST_TEMP) {
            $env:UPDATELOXONE_TEST_TEMP
        } else {
            # Fallback for running tests directly
            $fallbackTemp = Join-Path $PSScriptRoot "../temp/TestRun_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            if (-not (Test-Path $fallbackTemp)) {
                New-Item -ItemType Directory -Path $fallbackTemp -Force | Out-Null
            }
            $fallbackTemp
        }
        $listFile = Join-Path $tempPath "empty-integration.txt"
        $logFile = Join-Path $tempPath "integration-$(Get-Date -Format 'yyyyMMddHHmmss').log"
        
        # Create empty file
        "" | Out-File $listFile
        
        $result = Update-MS -DesiredVersion "14.0.0.0" `
            -ConfiguredUpdateChannel "Release" `
            -MSListPath $listFile `
            -LogFile $logFile `
            -MaxLogFileSizeMB 10 `
            -ScriptSaveFolder $tempPath
            
        # Update-MS returns either $null or empty array when no MS entries
        if ($null -ne $result) {
            $result | Should -BeOfType [System.Array]
            @($result).Count | Should -Be 0
        } else {
            $result | Should -BeNullOrEmpty
        }
    }
}