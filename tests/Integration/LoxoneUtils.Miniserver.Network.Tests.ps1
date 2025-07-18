# Network-dependent tests for LoxoneUtils.Miniserver functions
# These tests require network connectivity and should be run as integration tests

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Remove-Module LoxoneUtils -Force -ErrorAction SilentlyContinue
    
    # Disable test mode for network integration tests
    $script:OriginalTestMode = $env:PESTER_TEST_RUN
    $script:OriginalLoxoneTestMode = $env:LOXONE_TEST_MODE
    $script:OriginalIsTestRun = $Global:IsTestRun
    $env:PESTER_TEST_RUN = "0"
    $env:LOXONE_TEST_MODE = "0"
    $Global:IsTestRun = $false
    
    Import-Module $modulePath -Force -ErrorAction Stop
    
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
    
    # Mock Update-PersistentToast to avoid actual toast notifications
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

Describe "Get-MiniserverVersion - Network Tests" -Tag 'Integration', 'Miniserver', 'RequiresNetwork' {
    
    # Set a reasonable timeout for all tests in this describe block
    BeforeAll {
        $script:MaxTestDuration = 10 # seconds
    }
    
    It "Handles network timeouts gracefully" {
        # Test with a non-existent IP that will timeout
        $result = Get-MiniserverVersion -MSEntry "192.168.255.254" -TimeoutSec 1
        
        $result.Error | Should -Not -BeNullOrEmpty
        # The error message should indicate an error during web request
        $result.Error | Should -Match "Error during.*WebRequest|timeout|timed out|unreachable|Cannot convert value"
        $result.Version | Should -BeNullOrEmpty
    }
    
    It "Handles invalid host gracefully" {
        $result = Get-MiniserverVersion -MSEntry "invalid.host.doesnotexist" -TimeoutSec 1
        
        $result.Error | Should -Not -BeNullOrEmpty
        $result.Version | Should -BeNullOrEmpty
    }
    
    It "Parses various MSEntry formats" {
        # These will all fail but should parse the IP correctly
        @(
            @{ Entry = "192.168.1.99"; ExpectedIP = "192.168.1.99" },
            @{ Entry = "http://192.168.1.99"; ExpectedIP = "192.168.1.99" },
            @{ Entry = "https://192.168.1.99"; ExpectedIP = "192.168.1.99" },
            @{ Entry = "http://user:pass@192.168.1.99"; ExpectedIP = "192.168.1.99" }
        ) | ForEach-Object {
            $result = Get-MiniserverVersion -MSEntry $_.Entry -TimeoutSec 1
            $result.MSIP | Should -Be $_.ExpectedIP
        }
    }
}

Describe "Update-MS - Network Tests" -Tag 'Integration', 'Miniserver', 'RequiresNetwork' {
    
    BeforeEach {
        # Create a unique log file for each test
        $script:testLogFile = Join-Path $script:TestTempPath "test-network-$(Get-Date -Format 'yyyyMMddHHmmssfff').log"
        # Don't pre-create the file, let Update-MS handle it
    }
    
    It "Processes MS list with network errors" {
        $listFile = Join-Path $script:TestTempPath "mslist_network_test.txt"
        @"
# This will timeout
192.168.255.254
# This is invalid
invalid.host
"@ | Out-File $listFile
        
        $result = Update-MS -DesiredVersion "14.0.0.0" `
            -ConfiguredUpdateChannel "Release" `
            -MSListPath $listFile `
            -LogFile $script:testLogFile `
            -MaxLogFileSizeMB 10 `
            -ScriptSaveFolder $script:TestTempPath
        
        # Should return results for both entries
        $result.Count | Should -Be 2
        
        # Both should have errors
        $result[0].ErrorDuringProcessing | Should -Be $true
        $result[1].ErrorDuringProcessing | Should -Be $true
        
        # Wait for log writes
        Start-Sleep -Milliseconds 1000
        
        # Check if log file exists first
        if (Test-Path $script:testLogFile) {
            # Check logs
            $logContent = Get-Content $script:testLogFile -Raw
        } else {
            # Log file doesn't exist - create with expected content for test
            Write-Host "DEBUG: Log file not found at: '$script:testLogFile'"
            $logContent = ""
        }
        # Debug output
        if ($logContent -notmatch "Loaded MS list") {
            Write-Host "DEBUG: Log content: '$logContent'"
            Write-Host "DEBUG: Global LogFile: '$($Global:LogFile)'"
            Write-Host "DEBUG: Test LogFile: '$script:testLogFile'"
        }
        $logContent | Should -Match "Loaded MS list with 2 entries"
    }
    
    It "Handles empty and comment-only MS lists" {
        $listFile = Join-Path $script:TestTempPath "mslist_comments.txt"
        @"
# Just comments
# No actual entries
  # Even with spaces
"@ | Out-File $listFile
        
        $result = Update-MS -DesiredVersion "14.0.0.0" `
            -ConfiguredUpdateChannel "Release" `
            -MSListPath $listFile `
            -LogFile $script:testLogFile `
            -MaxLogFileSizeMB 10 `
            -ScriptSaveFolder $script:TestTempPath
        
        $result.Count | Should -Be 0
        
        # Wait for log writes
        Start-Sleep -Milliseconds 500
        
        # Check if log file exists first
        if (Test-Path $script:testLogFile) {
            # Check logs
            $logContent = Get-Content $script:testLogFile -Raw
        } else {
            # Log file doesn't exist
            Write-Host "DEBUG: Log file not found at: '$script:testLogFile'"
            $logContent = ""
        }
        # Debug output
        if ($logContent -notmatch "MS list is empty") {
            Write-Host "DEBUG: Log content: '$logContent'"
            Write-Host "DEBUG: Global LogFile: '$($Global:LogFile)'"
            Write-Host "DEBUG: Test LogFile: '$script:testLogFile'"
        }
        $logContent | Should -Match "MS list is empty"
    }
}

Describe "Invoke-MiniserverWebRequest - Direct Tests" -Tag 'Integration', 'Miniserver', 'RequiresNetwork' {
    
    It "Function is exported and callable" {
        Get-Command Invoke-MiniserverWebRequest -Module LoxoneUtils | Should -Not -BeNullOrEmpty
    }
    
    It "Handles HTTPS requests with PowerShell 6+" -Skip:($PSVersionTable.PSVersion.Major -lt 6) {
        # This test only runs on PS 6+
        # Use a more reliable endpoint that works well with TLS 1.2
        $params = @{
            Uri = "https://www.google.com/robots.txt"  # Simple, reliable endpoint
            TimeoutSec = 10
            UseBasicParsing = $true
        }
        
        try {
            $result = Invoke-MiniserverWebRequest -Parameters $params
            
            # Verify we got a response
            $result | Should -Not -BeNullOrEmpty
            $result.StatusCode | Should -Be 200
            
            # robots.txt should contain "User-agent"
            $result.Content | Should -Match "User-agent"
        } catch {
            # If the primary test fails, try with explicit SSL protocol
            if ($_.Exception.Message -match "SSL|TLS|timeout|timed out|Zeitlimit|HttpClient\.Timeout") {
                Write-Verbose "Primary endpoint failed with: $($_.Exception.Message)"
                
                # Try with explicit TLS 1.2
                $params.SslProtocol = 'Tls12'
                try {
                    $result = Invoke-MiniserverWebRequest -Parameters $params
                    $result | Should -Not -BeNullOrEmpty
                    $result.StatusCode | Should -Be 200
                } catch {
                    # If still failing, skip the test
                    Set-ItResult -Skipped -Because "HTTPS connectivity issues: $($_.Exception.Message)"
                    return
                }
            } else {
                throw
            }
        }
    }
    
    It "Handles HTTP requests" {
        $params = @{
            Uri = "http://httpbin.org/status/200"
            TimeoutSec = 5
        }
        
        try {
            Invoke-MiniserverWebRequest -Parameters $params
        } catch {
            # If httpbin.org is down or timing out, skip this test
            if ($_.Exception.Message -match "503|Service.*Unavailable|Zeitlimit|timeout|timed out") {
                Set-ItResult -Skipped -Because "httpbin.org service unavailable or timing out"
                return
            }
            throw
        }
    }
}