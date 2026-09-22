# Coverage tests for LoxoneUtils.MiniserverHardware - Get-MiniserverGeneration
# Tests generation determination logic based on serial numbers, hardware IDs, and URL schemes

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

    $script:TestTempPath = Join-Path $TestDrive "HardwareCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Get-MiniserverGeneration" -Tag 'Unit', 'MiniserverHardware' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Get-MiniserverGeneration -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should accept SerialNumber, HardwareId, and MSEntry parameters" {
            $cmd = Get-Command Get-MiniserverGeneration
            $cmd.Parameters.Keys | Should -Contain 'SerialNumber'
            $cmd.Parameters.Keys | Should -Contain 'HardwareId'
            $cmd.Parameters.Keys | Should -Contain 'MSEntry'
        }
    }

    Context "HTTPS-based detection" {

        It "Should return Gen2 when MSEntry starts with https://" {
            $result = Get-MiniserverGeneration -MSEntry 'https://admin:pass@10.3.98.5'
            $result | Should -Be 'Gen2'
        }

        It "Should not return Gen2 for http:// entries" {
            $result = Get-MiniserverGeneration -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Not -Be 'Gen2'
        }
    }

    Context "Serial number-based detection" {

        It "Should return Gen1 for classic serial number pattern (5 + 11 hex = 12 chars)" {
            # The regex is ^5[0-9A-F]{11}$ which requires exactly 12 characters
            $result = Get-MiniserverGeneration -SerialNumber '5AABBCCDDEEF' -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Be 'Gen1'
        }

        It "Should not match Gen1 serial pattern for non-matching serial" {
            # Serial that does not start with 5 or is wrong length
            $result = Get-MiniserverGeneration -SerialNumber 'ZZZZ' -MSEntry 'http://admin:pass@192.168.1.10'
            # Should fall through to other checks or Unknown
            $result | Should -Not -Be 'Gen1'
        }
    }

    Context "Hardware ID-based detection" {

        It "Should return Gen1-Grey for hardware ID A0000" {
            $result = Get-MiniserverGeneration -HardwareId 'A0000' -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Be 'Gen1-Grey'
        }

        It "Should not match Gen1-Grey for other hardware IDs" {
            $result = Get-MiniserverGeneration -HardwareId 'B1234' -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Not -Be 'Gen1-Grey'
        }
    }

    Context "Fallback behavior" {

        It "Should return Unknown when no detection criteria match" {
            $result = Get-MiniserverGeneration -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Be 'Unknown'
        }

        It "Should return Unknown with empty parameters" {
            $result = Get-MiniserverGeneration -SerialNumber '' -HardwareId '' -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Be 'Unknown'
        }
    }

    Context "Priority of detection methods" {

        It "Should prioritize HTTPS detection over serial number" {
            # HTTPS URL but with a Gen1 serial pattern
            $result = Get-MiniserverGeneration -SerialNumber '5AABBCCDDEE' -MSEntry 'https://admin:pass@10.3.98.5'
            $result | Should -Be 'Gen2'
        }

        It "Should prioritize serial number over hardware ID" {
            # Gen1 serial (12 chars) with Gen1-Grey hardware ID - serial check comes first
            $result = Get-MiniserverGeneration -SerialNumber '5AABBCCDDEEF' -HardwareId 'A0000' -MSEntry 'http://admin:pass@192.168.1.10'
            $result | Should -Be 'Gen1'
        }
    }
}

Describe "Get-MiniserverHardwareInfo" -Tag 'Unit', 'MiniserverHardware' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Get-MiniserverHardwareInfo -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
        }

        It "Should have mandatory MSEntry parameter" {
            $cmd = Get-Command Get-MiniserverHardwareInfo
            $cmd.Parameters['MSEntry'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
        }

        It "Should accept SkipCertificateCheck and TimeoutSec parameters" {
            $cmd = Get-Command Get-MiniserverHardwareInfo
            $cmd.Parameters.Keys | Should -Contain 'SkipCertificateCheck'
            $cmd.Parameters.Keys | Should -Contain 'TimeoutSec'
        }
    }
}

Describe "Test-MiniserverRequiresHTTPS" -Tag 'Unit', 'MiniserverHardware' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Test-MiniserverRequiresHTTPS -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
        }

        It "Should have mandatory MSEntry parameter" {
            $cmd = Get-Command Test-MiniserverRequiresHTTPS
            $cmd.Parameters['MSEntry'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
        }
    }
}
