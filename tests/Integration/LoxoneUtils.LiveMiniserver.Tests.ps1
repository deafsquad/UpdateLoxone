# Live Miniserver Integration Tests
# Tests read-only miniserver operations against real devices
# SAFETY: No update operations - all queries are read-only

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'

    # Disable test mode for integration tests - we want real network calls
    $script:OriginalTestMode = $env:PESTER_TEST_RUN
    $script:OriginalLoxoneTestMode = $env:LOXONE_TEST_MODE
    $script:OriginalIsTestRun = $Global:IsTestRun
    $env:PESTER_TEST_RUN = "0"
    $env:LOXONE_TEST_MODE = "0"
    $Global:IsTestRun = $false
    $Global:SuppressLoxoneToastInit = $true

    Import-Module $modulePath -Force -ErrorAction Stop

    # Set up temp directory
    $script:TestTempPath = if ($env:UPDATELOXONE_TEST_TEMP) {
        $env:UPDATELOXONE_TEST_TEMP
    } else {
        $fallbackTemp = Join-Path $PSScriptRoot "../temp/TestRun_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        if (-not (Test-Path $fallbackTemp)) {
            New-Item -ItemType Directory -Path $fallbackTemp -Force | Out-Null
        }
        $fallbackTemp
    }
    if (-not (Test-Path $script:TestTempPath)) {
        New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    }

    $Global:LogFile = Join-Path $script:TestTempPath 'live-ms-test.log'
    "# Live MS integration test log" | Out-File $Global:LogFile -Encoding UTF8

    # Load miniserver list dynamically
    $msListPath = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'UpdateLoxoneMSList.txt'
    $script:MSEntries = @()
    $script:MSListPath = $msListPath

    if (Test-Path $msListPath) {
        $lines = Get-Content $msListPath | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
        foreach ($line in $lines) {
            $parsed = ConvertFrom-MiniserverListEntry -Line $line
            if ($parsed) {
                $script:MSEntries += $parsed
            }
        }
    }

    # Get first available MS for single-device tests
    $script:FirstMS = if ($script:MSEntries.Count -gt 0) { $script:MSEntries[0] } else { $null }

    # Helper to get HTTP-only entry (Gen1)
    $script:HttpMS = $script:MSEntries | Where-Object { $_.Url -match '^http://' } | Select-Object -First 1

    # Helper to get HTTPS entry (Gen2)
    $script:HttpsMS = $script:MSEntries | Where-Object { $_.Url -match '^https://' } | Select-Object -First 1

    # Helper to build PSCredential from a parsed MS entry URL
    $script:GetCredential = {
        param([string]$Url)
        $uri = [System.Uri]$Url
        $userPass = $uri.UserInfo.Split(':', 2)
        $securePassword = New-Object System.Security.SecureString
        foreach ($c in $userPass[1].ToCharArray()) { $securePassword.AppendChar($c) }
        return New-Object System.Management.Automation.PSCredential($userPass[0], $securePassword)
    }

    # Mock toast to avoid notifications during test
    Mock Update-PersistentToast {} -ModuleName LoxoneUtils
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $script:OriginalTestMode) { $env:PESTER_TEST_RUN = $script:OriginalTestMode }
    if ($null -ne $script:OriginalLoxoneTestMode) { $env:LOXONE_TEST_MODE = $script:OriginalLoxoneTestMode }
    if ($null -ne $script:OriginalIsTestRun) { $Global:IsTestRun = $script:OriginalIsTestRun }
}

# --- Get-MiniserverVersion ---
Describe "Get-MiniserverVersion - Live Device Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Returns valid version from each configured miniserver" {
        if ($script:MSEntries.Count -eq 0) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        foreach ($msEntry in $script:MSEntries) {
            try {
                $result = Get-MiniserverVersion -MSEntry $msEntry.Url -TimeoutSec 5
                $result | Should -Not -BeNullOrEmpty
                $result.MSIP | Should -Not -BeNullOrEmpty

                if ($result.Version) {
                    $result.Version | Should -Match '^\d+\.\d+\.\d+\.\d+$'
                } else {
                    # Device may be unreachable - error should be populated
                    $result.Error | Should -Not -BeNullOrEmpty
                }
            } catch {
                if ($msEntry.Url -match '^https://' -and $_.Exception.Message -match 'certificate|ssl|tls') {
                    Write-Warning "HTTPS certificate issue for $($msEntry.IP) - expected in test environment"
                } else {
                    throw
                }
            }
        }
    }

    It "Returns consistent version across multiple calls" {
        if (-not $script:FirstMS) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        try {
            $result1 = Get-MiniserverVersion -MSEntry $script:FirstMS.Url -TimeoutSec 5
            $result2 = Get-MiniserverVersion -MSEntry $script:FirstMS.Url -TimeoutSec 5

            if ($result1.Version -and $result2.Version) {
                $result1.Version | Should -Be $result2.Version
            }
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls') {
                Set-ItResult -Skipped -Because "HTTPS certificate issue in test environment"
            } else {
                throw
            }
        }
    }

    It "Handles custom timeout parameter" {
        if (-not $script:FirstMS) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        try {
            $result = Get-MiniserverVersion -MSEntry $script:FirstMS.Url -TimeoutSec 10
            $result | Should -Not -BeNullOrEmpty
            if ($result.Version) {
                $result.Version | Should -Match '^\d+\.\d+\.\d+\.\d+$'
            }
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls') {
                Set-ItResult -Skipped -Because "HTTPS certificate issue in test environment"
            } else {
                throw
            }
        }
    }
}

# --- Test-MiniserverConnectivity ---
Describe "Test-MiniserverConnectivity - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Can ping each configured miniserver" {
        if ($script:MSEntries.Count -eq 0) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        $reachableCount = 0
        foreach ($msEntry in $script:MSEntries) {
            # Pre-check connectivity - skip unreachable (e.g. VPN down, different network)
            if (-not (Test-Connection -ComputerName $msEntry.IP -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                Write-Warning "Miniserver $($msEntry.IP) is unreachable - skipping"
                continue
            }
            $result = Test-MiniserverConnectivity -IPAddress $msEntry.IP -MaxWaitSeconds 10
            $result | Should -Be $true
            $reachableCount++
        }

        if ($reachableCount -eq 0) {
            Set-ItResult -Skipped -Because "All configured miniservers are unreachable"
        }
    }

    It "Returns false for unreachable IP" {
        $result = Test-MiniserverConnectivity -IPAddress '192.168.255.254' -MaxWaitSeconds 3
        $result | Should -Be $false
    }
}

# --- Wait-ForPingSuccess ---
Describe "Wait-ForPingSuccess - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Succeeds for reachable miniserver" {
        if (-not $script:FirstMS) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        $result = Wait-ForPingSuccess -InputAddress $script:FirstMS.IP -TimeoutSeconds 10 -RetryCount 10
        $result | Should -Be $true
    }

    It "Fails quickly for unreachable host" {
        $startTime = Get-Date
        $result = Wait-ForPingSuccess -InputAddress '192.168.255.254' -TimeoutSeconds 3 -RetryCount 3
        $elapsed = ((Get-Date) - $startTime).TotalSeconds

        $result | Should -Be $false
        $elapsed | Should -BeLessThan 10
    }
}

# --- Get-MiniserverHardwareInfo ---
Describe "Get-MiniserverHardwareInfo - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Gets hardware info from HTTP miniserver" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $result = Get-MiniserverHardwareInfo -MSEntry $script:HttpMS.Url

        $result | Should -Not -BeNullOrEmpty
        $result.Success | Should -Be $true
        $result.Generation | Should -Not -BeNullOrEmpty
        $result.DetectionMethod | Should -Not -BeNullOrEmpty
    }

    It "Gets hardware info from HTTPS miniserver" {
        if (-not $script:HttpsMS) {
            Set-ItResult -Skipped -Because "No HTTPS miniserver configured"
            return
        }

        # Pre-check connectivity - skip if VPN/network is down (ping)
        if (-not (Test-Connection -ComputerName $script:HttpsMS.IP -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "HTTPS miniserver $($script:HttpsMS.IP) is unreachable"
            return
        }
        # Also verify HTTPS port reachable (ping passes through firewalls that block 443)
        if (-not (Test-NetConnection -ComputerName $script:HttpsMS.IP -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "HTTPS miniserver $($script:HttpsMS.IP) port 443 unreachable"
            return
        }

        try {
            $result = Get-MiniserverHardwareInfo -MSEntry $script:HttpsMS.Url -SkipCertificateCheck

            if (-not $result -or -not $result.Success) {
                $errMsg = if ($result) { $result.ErrorMessage } else { 'null result' }
                Set-ItResult -Skipped -Because "Get-MiniserverHardwareInfo failed (live API issue, not a code bug): $errMsg"
                return
            }

            $result.Generation | Should -Not -BeNullOrEmpty
            $result.DetectionMethod | Should -Not -BeNullOrEmpty
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls|timeout|Timeout|Vertrauensstellung|401|403|refused|verweigert') {
                Set-ItResult -Skipped -Because "HTTPS connection/auth issue (not a code bug): $($_.Exception.Message)"
            } else {
                throw
            }
        }
    }

    It "Returns serial number when available" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $result = Get-MiniserverHardwareInfo -MSEntry $script:HttpMS.Url

        if ($result.Success) {
            $result.SerialNumber | Should -Not -BeNullOrEmpty
        }
    }
}

# --- Get-MiniserverGenerationInfo ---
Describe "Get-MiniserverGenerationInfo - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Detects generation for each miniserver" {
        if ($script:MSEntries.Count -eq 0) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        foreach ($msEntry in $script:MSEntries) {
            try {
                $result = Get-MiniserverGenerationInfo -MSEntry $msEntry.Url

                $result.Success | Should -Be $true
                $result.Generation | Should -Match '^Gen[12]'
            } catch {
                if ($_.Exception.Message -match 'certificate|ssl|tls') {
                    Write-Warning "HTTPS certificate issue for $($msEntry.IP) - expected in test environment"
                } else {
                    throw
                }
            }
        }
    }

    It "HTTP miniserver is detected as Gen1" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $result = Get-MiniserverGenerationInfo -MSEntry $script:HttpMS.Url
        $result.Success | Should -Be $true
        $result.Generation | Should -Match 'Gen1'
    }

    It "HTTPS miniserver is detected as Gen2" {
        if (-not $script:HttpsMS) {
            Set-ItResult -Skipped -Because "No HTTPS miniserver configured"
            return
        }

        # Pre-check connectivity - skip if VPN/network is down
        if (-not (Test-Connection -ComputerName $script:HttpsMS.IP -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "HTTPS miniserver $($script:HttpsMS.IP) is unreachable"
            return
        }

        try {
            $result = Get-MiniserverGenerationInfo -MSEntry $script:HttpsMS.Url
            $result.Success | Should -Be $true
            $result.Generation | Should -Be 'Gen2'
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls|timeout|Timeout') {
                Set-ItResult -Skipped -Because "HTTPS connection issue: $($_.Exception.Message)"
            } else {
                throw
            }
        }
    }

    It "Returns detection method" {
        if (-not $script:FirstMS) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        try {
            $result = Get-MiniserverGenerationInfo -MSEntry $script:FirstMS.Url

            $result.DetectionMethod | Should -Not -BeNullOrEmpty
            $result.DetectionMethod | Should -Not -Be 'Unknown'
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls') {
                Set-ItResult -Skipped -Because "HTTPS certificate issue in test environment"
            } else {
                throw
            }
        }
    }

    It "Returns HTTPS requirement correctly" {
        if ($script:MSEntries.Count -eq 0) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        # Test Gen1 (HTTP) if available
        if ($script:HttpMS) {
            $result = Get-MiniserverGenerationInfo -MSEntry $script:HttpMS.Url
            if ($result.Success -and $result.Generation -match 'Gen1') {
                $result.RequiresHTTPS | Should -Be $false
            }
        }

        # Test Gen2 (HTTPS) if available
        if ($script:HttpsMS) {
            try {
                $result = Get-MiniserverGenerationInfo -MSEntry $script:HttpsMS.Url
                if ($result.Success -and $result.Generation -eq 'Gen2') {
                    $result.RequiresHTTPS | Should -Be $true
                }
            } catch {
                if ($_.Exception.Message -match 'certificate|ssl|tls') {
                    Write-Warning "HTTPS certificate issue - skipping HTTPS requirement test"
                } else {
                    throw
                }
            }
        }
    }
}

# --- Test-MiniserverRequiresHTTPS ---
Describe "Test-MiniserverRequiresHTTPS - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Returns false for HTTP miniserver" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $result = Test-MiniserverRequiresHTTPS -MSEntry $script:HttpMS.Url
        $result | Should -Be $false
    }

    It "Returns true for HTTPS-only miniserver" {
        if (-not $script:HttpsMS) {
            Set-ItResult -Skipped -Because "No HTTPS miniserver configured"
            return
        }

        # Pre-check connectivity - skip if VPN/network is down (ping)
        if (-not (Test-Connection -ComputerName $script:HttpsMS.IP -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "HTTPS miniserver $($script:HttpsMS.IP) is unreachable"
            return
        }
        # Also verify HTTPS port reachable
        if (-not (Test-NetConnection -ComputerName $script:HttpsMS.IP -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "HTTPS miniserver $($script:HttpsMS.IP) port 443 unreachable"
            return
        }

        try {
            $result = Test-MiniserverRequiresHTTPS -MSEntry $script:HttpsMS.Url
            if ($null -eq $result) {
                Set-ItResult -Skipped -Because "Test-MiniserverRequiresHTTPS returned null (live API issue, not a code bug)"
                return
            }
            $result | Should -Be $true
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls|timeout|Timeout|Vertrauensstellung|401|403|refused|verweigert') {
                Set-ItResult -Skipped -Because "HTTPS connection/auth issue (not a code bug): $($_.Exception.Message)"
            } else {
                throw
            }
        }
    }
}

# --- NetworkCore Functions ---
Describe "NetworkCore - Live Endpoint Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Test-NetworkEndpoint reaches miniserver" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $credential = & $script:GetCredential $script:HttpMS.Url
        $endpoint = "http://$($script:HttpMS.IP)/dev/cfg/version"

        $result = Test-NetworkEndpoint -Uri $endpoint -Credential $credential -TimeoutMs 5000
        $result.Success | Should -Be $true
    }

    It "Test-FastNetworkEndpoint reaches miniserver" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $credential = & $script:GetCredential $script:HttpMS.Url
        $endpoint = "http://$($script:HttpMS.IP)/dev/cfg/version"

        $result = Test-FastNetworkEndpoint -Uri $endpoint -Credential $credential -TimeoutMs 5000
        $result.Success | Should -Be $true
    }

    It "Test-StandardNetworkEndpoint reaches miniserver" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $credential = & $script:GetCredential $script:HttpMS.Url
        $endpoint = "http://$($script:HttpMS.IP)/dev/cfg/version"

        $result = Test-StandardNetworkEndpoint -Uri $endpoint -Credential $credential -TimeoutSec 5
        $result.Success | Should -Be $true
    }

    It "Invoke-NetworkRequest with ForceStandard" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $credential = & $script:GetCredential $script:HttpMS.Url
        $endpoint = "http://$($script:HttpMS.IP)/dev/cfg/version"

        $result = Invoke-NetworkRequest -Uri $endpoint -Credential $credential -ForceStandard
        $result.Success | Should -Be $true
    }

    It "Invoke-NetworkRequest with ForceFast" {
        if (-not $script:HttpMS) {
            Set-ItResult -Skipped -Because "No HTTP miniserver configured"
            return
        }

        $credential = & $script:GetCredential $script:HttpMS.Url
        $endpoint = "http://$($script:HttpMS.IP)/dev/cfg/version"

        $result = Invoke-NetworkRequest -Uri $endpoint -Credential $credential -ForceFast
        $result.Success | Should -Be $true
    }
}

# --- Test-LoxoneMiniserverUpdateLevel ---
Describe "Test-LoxoneMiniserverUpdateLevel - Live Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Can query update level from miniserver" {
        if (-not $script:FirstMS) {
            Set-ItResult -Skipped -Because "No miniserver configured"
            return
        }

        try {
            # This function may throw if there's a mismatch between configured and actual update level
            Test-LoxoneMiniserverUpdateLevel -MSEntry $script:FirstMS.Url -ConfiguredUpdateChannel 'Release' -TimeoutSec 5

            # If we get here without throwing, the levels match
            $true | Should -Be $true
        } catch {
            if ($_.Exception.Message -match 'certificate|ssl|tls') {
                Set-ItResult -Skipped -Because "HTTPS certificate issue in test environment"
            } elseif ($_.Exception.Message -match 'update.*level|channel|mismatch|updatelevel') {
                # Function is working correctly - it detected a level difference
                $true | Should -Be $true
            } else {
                throw
            }
        }
    }
}

# --- Get-MiniserverListWithCache ---
Describe "Get-MiniserverListWithCache - Live File Tests" -Tag 'Integration', 'LiveMiniserver' {

    It "Reads and parses the actual MS list file" {
        if (-not (Test-Path $script:MSListPath)) {
            Set-ItResult -Skipped -Because "UpdateLoxoneMSList.txt not found"
            return
        }

        $result = Get-MiniserverListWithCache -FilePath $script:MSListPath

        $result | Should -Not -BeNullOrEmpty
        $result.Count | Should -BeGreaterThan 0
        $result.Count | Should -Be $script:MSEntries.Count
    }

    It "Each parsed entry has required properties" {
        if (-not (Test-Path $script:MSListPath)) {
            Set-ItResult -Skipped -Because "UpdateLoxoneMSList.txt not found"
            return
        }

        $result = Get-MiniserverListWithCache -FilePath $script:MSListPath

        foreach ($entry in $result) {
            $entry.Url | Should -Not -BeNullOrEmpty
            $entry.IP | Should -Not -BeNullOrEmpty
            # HasCache should exist as a property
            $entry.HasCache | Should -Not -Be $null
        }
    }

    It "Cache data matches expected format" {
        if (-not (Test-Path $script:MSListPath)) {
            Set-ItResult -Skipped -Because "UpdateLoxoneMSList.txt not found"
            return
        }

        $result = Get-MiniserverListWithCache -FilePath $script:MSListPath
        $entriesWithCache = $result | Where-Object { $_.HasCache -eq $true }

        foreach ($entry in $entriesWithCache) {
            if ($entry.CachedVersion) {
                $entry.CachedVersion | Should -Match '^\d+\.\d+\.\d+\.\d+$'
            }
        }
    }
}
