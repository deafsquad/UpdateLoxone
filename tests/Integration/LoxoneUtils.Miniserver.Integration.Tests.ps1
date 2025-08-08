# Integration tests for LoxoneUtils.Miniserver that require network connectivity
# These tests should only run when explicitly requested with -TestType Integration or All

# Import the module at script level
$modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'

# Disable test mode for integration tests
$script:OriginalTestMode = $env:PESTER_TEST_RUN
$script:OriginalLoxoneTestMode = $env:LOXONE_TEST_MODE
$script:OriginalIsTestRun = $Global:IsTestRun
$env:PESTER_TEST_RUN = "0"
$env:LOXONE_TEST_MODE = "0"
$Global:IsTestRun = $false

Import-Module $modulePath -Force -ErrorAction Stop

BeforeAll {
    # Set up temp directory using test isolation
    $script:TestTempPath = if ($env:UPDATELOXONE_TEST_TEMP) {
        $env:UPDATELOXONE_TEST_TEMP
    } else {
        # Fallback for running tests directly
        $fallbackTemp = Join-Path $PSScriptRoot "../temp/TestRun_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        if (-not (Test-Path $fallbackTemp)) {
            New-Item -ItemType Directory -Path $fallbackTemp -Force | Out-Null
        }
        $fallbackTemp
    }
    
    # Ensure temp directory exists
    if (-not (Test-Path $script:TestTempPath)) {
        New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    }
    
    # Set up logging
    $Global:LogFile = Join-Path $script:TestTempPath 'integration-test.log'
    "# Integration test log" | Out-File $Global:LogFile -Encoding UTF8
    
    # Mock Update-PersistentToast to avoid actual toast notifications
    Mock Update-PersistentToast {} -ModuleName LoxoneUtils
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    
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

Describe "Update-MS Function - Network Error Handling" -Tag 'Integration', 'RequiresNetwork' {
    
    It "Can process MS list with invalid hostname" {
        $listFile = Join-Path $script:TestTempPath "mslist_invalid.txt"
        @"
# Test with invalid hostname - should fail quickly with DNS error
http://invalid.miniserver.test
"@ | Out-File $listFile
        
        # This will fail quickly with DNS resolution error
        # Don't suppress errors - let's see what happens
        $result = Update-MS -DesiredVersion "13.0.4.44" `
            -ConfiguredUpdateChannel "Release" `
            -MSListPath $listFile `
            -LogFile $Global:LogFile `
            -MaxLogFileSizeMB 10 `
            -ScriptSaveFolder $script:TestTempPath
        
        # Should process entry and record error
        $result | Should -Not -BeNullOrEmpty
        
        # PowerShell unwraps single-item arrays, so we need to handle both cases
        if ($result -is [array]) {
            $result.Count | Should -Be 1
            $result[0].ErrorDuringProcessing | Should -Be $true
        } else {
            # Single object returned
            $result.MSEntry | Should -Not -BeNullOrEmpty
            $result.ErrorDuringProcessing | Should -Be $true
        }
    }
    
    It "Can handle mixed valid and invalid entries" {
        $listFile = Join-Path $script:TestTempPath "mslist_mixed.txt"
        @"
# Mix of valid format entries that will fail in different ways
http://invalid.host.test
http://localhost:65001
"@ | Out-File $listFile
        
        $result = Update-MS -DesiredVersion "13.0.4.44" `
            -ConfiguredUpdateChannel "Release" `
            -MSListPath $listFile `
            -LogFile $Global:LogFile `
            -MaxLogFileSizeMB 10 `
            -ScriptSaveFolder $script:TestTempPath
        
        # Should process both entries
        $result.Count | Should -Be 2
        # Both should have errors
        $result | Where-Object { $_.ErrorDuringProcessing -eq $true } | Should -HaveCount 2
    }
}

Describe "Get-MiniserverVersion - Real Device Tests" -Tag 'Integration', 'RequiresNetwork', 'RequiresRealDevice' {
    
    BeforeAll {
        # First try test miniserver list, then fall back to real list
        $testListPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'TestMiniserverList.txt'
        $msListPath = if (Test-Path $testListPath) {
            Write-Host "Using test miniserver list" -ForegroundColor Yellow
            $testListPath
        } else {
            Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'UpdateLoxoneMSList.txt'
        }
        
        if (Test-Path $msListPath) {
            # Read first non-comment entry from MS list
            $msEntries = Get-Content $msListPath | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
            if ($msEntries -and $msEntries.Count -gt 0) {
                # Get first entry - Get-MiniserverVersion will handle URL parsing
                $script:RealDeviceEntry = $msEntries[0]
                Write-Host "Using MS entry from list: $($script:RealDeviceEntry -replace '(:)[^:@]+(@)', '$1****$2')" -ForegroundColor Cyan
            }
        }
        
        # Fall back to environment variables if no list
        if (-not $script:RealDeviceEntry) {
            $script:RealDeviceIP = $env:LOXONE_TEST_DEVICE_IP
            $script:RealDeviceUser = $env:LOXONE_TEST_DEVICE_USER
            $script:RealDevicePass = $env:LOXONE_TEST_DEVICE_PASS
            
            if ($script:RealDeviceIP -and $script:RealDeviceUser -and $script:RealDevicePass) {
                $script:RealDeviceEntry = "http://$($script:RealDeviceUser):$($script:RealDevicePass)@$($script:RealDeviceIP)"
            }
        }
        
        if (-not $script:RealDeviceEntry) {
            Write-Host "No real device available for testing (no MS list found and LOXONE_TEST_DEVICE_IP not set)" -ForegroundColor Yellow
        }
    }
    
    It "Can connect to real Miniserver" {
        if (-not $script:RealDeviceEntry) { 
            Set-ItResult -Skipped -Because "No real device configured"
            return 
        }
        
        $result = Get-MiniserverVersion -MSEntry $script:RealDeviceEntry -TimeoutSec 5
        
        # If it times out or fails, that's OK - we're testing the function works
        $result | Should -Not -BeNullOrEmpty
        $result.MSIP | Should -Not -BeNullOrEmpty
        
        # If we got a version, verify format
        if ($result.Version) {
            $result.Version | Should -Match '^\d+\.\d+\.\d+\.\d+$'
        } else {
            # Error is expected if device is offline
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}