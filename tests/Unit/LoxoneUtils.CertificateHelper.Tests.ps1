# Unit tests for LoxoneUtils.CertificateHelper
# Tests Set-CertificateValidationBypass and Clear-CertificateValidationBypass

BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    $Global:SuppressLoxoneToastInit = $true

    $script:TestTempPath = Join-Path $TestDrive "CacheTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    # Restore normal certificate validation after all tests
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Set-CertificateValidationBypass" -Tag 'Unit' {

    AfterEach {
        # Clean up after each test so they remain independent
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    It "Should return $true on success" {
        $result = Set-CertificateValidationBypass
        $result | Should -Be $true
    }

    It "Should set the ServerCertificateValidationCallback to a non-null delegate" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -Not -BeNullOrEmpty
    }

    It "Should set SecurityProtocol to TLS 1.2" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::SecurityProtocol | Should -Be ([System.Net.SecurityProtocolType]::Tls12)
    }

    It "Should set Expect100Continue to false" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::Expect100Continue | Should -Be $false
    }

    It "Should set DefaultConnectionLimit to 10" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::DefaultConnectionLimit | Should -Be 10
    }

    It "Should register a CertificateValidator type in the AppDomain" {
        Set-CertificateValidationBypass | Out-Null

        $type = [System.AppDomain]::CurrentDomain.GetAssemblies() |
            ForEach-Object { $_.GetTypes() } |
            Where-Object { $_.Name -eq 'CertificateValidator' } |
            Select-Object -First 1

        $type | Should -Not -BeNullOrEmpty
        $type.Name | Should -Be 'CertificateValidator'
    }

    It "Should be idempotent - calling twice returns $true both times without error" {
        $result1 = Set-CertificateValidationBypass
        $result2 = Set-CertificateValidationBypass

        $result1 | Should -Be $true
        $result2 | Should -Be $true
    }

    It "Should produce a callback delegate whose AcceptAll method returns $true" {
        Set-CertificateValidationBypass | Out-Null

        $callback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        # Invoke the delegate with null arguments - AcceptAll ignores them and returns true
        $accepted = $callback.Invoke($null, $null, $null, [System.Net.Security.SslPolicyErrors]::None)
        $accepted | Should -Be $true
    }
}

Describe "Clear-CertificateValidationBypass" -Tag 'Unit' {

    It "Should return $true on success" {
        # First set the bypass so there is something to clear
        Set-CertificateValidationBypass | Out-Null
        $result = Clear-CertificateValidationBypass
        $result | Should -Be $true
    }

    It "Should set ServerCertificateValidationCallback back to null" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -Not -BeNullOrEmpty

        Clear-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -BeNullOrEmpty
    }

    It "Should be safe to call when no bypass is set" {
        # Ensure callback is already null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

        $result = Clear-CertificateValidationBypass
        $result | Should -Be $true
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -BeNullOrEmpty
    }

    It "Should be idempotent - calling twice returns $true both times" {
        Set-CertificateValidationBypass | Out-Null

        $result1 = Clear-CertificateValidationBypass
        $result2 = Clear-CertificateValidationBypass

        $result1 | Should -Be $true
        $result2 | Should -Be $true
    }
}

Describe "Set and Clear round-trip" -Tag 'Unit' {

    AfterEach {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }

    It "Should restore null callback after Set then Clear" {
        Set-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -Not -BeNullOrEmpty

        Clear-CertificateValidationBypass | Out-Null
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -BeNullOrEmpty
    }

    It "Should allow multiple Set/Clear cycles without error" {
        for ($i = 0; $i -lt 3; $i++) {
            Set-CertificateValidationBypass | Should -Be $true
            Clear-CertificateValidationBypass | Should -Be $true
        }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback | Should -BeNullOrEmpty
    }
}
