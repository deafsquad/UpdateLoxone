# Regression tests for CRC32 comparison in Invoke-LoxoneDownload.
# Bug (2026-08-02): Get-CRC32 returns ToString("X8") (zero-padded to 8 chars) but Loxone's
# updatecheck.xml strips leading zeros - the App InternalV2 channel published crc32="404699"
# for a file whose real CRC is "00404699". The old comparison only normalized the specific
# case "local is 8 chars starting with 0 AND expected is exactly 7 chars", so the 6-char value
# fell through, a perfectly good App download was rejected twice, and the App update aborted.
# 8 of 136 crc32 attributes in the live XML are shorter than 8 chars.
BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) { Import-Module $modulePath -ErrorAction Stop }
    }
}

Describe 'ConvertTo-NormalizedCRC32' -Tag 'Unit' {
    It 'pads a zero-stripped value to canonical 8-char uppercase form' {
        InModuleScope LoxoneUtils.Network {
            ConvertTo-NormalizedCRC32 '404699'  | Should -Be '00404699'
            ConvertTo-NormalizedCRC32 'f415607' | Should -Be '0F415607'
            ConvertTo-NormalizedCRC32 '8e6c11'  | Should -Be '008E6C11'
        }
    }

    It 'leaves an already-canonical value unchanged (uppercased)' {
        InModuleScope LoxoneUtils.Network {
            ConvertTo-NormalizedCRC32 '00404699' | Should -Be '00404699'
            ConvertTo-NormalizedCRC32 'e487dd39' | Should -Be 'E487DD39'
        }
    }

    It 'trims surrounding whitespace' {
        InModuleScope LoxoneUtils.Network {
            ConvertTo-NormalizedCRC32 "  404699 `t" | Should -Be '00404699'
        }
    }

    It 'returns null for absent or non-hex values' {
        InModuleScope LoxoneUtils.Network {
            ConvertTo-NormalizedCRC32 $null       | Should -BeNullOrEmpty
            ConvertTo-NormalizedCRC32 ''          | Should -BeNullOrEmpty
            ConvertTo-NormalizedCRC32 '   '       | Should -BeNullOrEmpty
            ConvertTo-NormalizedCRC32 'nothex!'   | Should -BeNullOrEmpty
            ConvertTo-NormalizedCRC32 '123456789' | Should -BeNullOrEmpty  # too long for CRC32
        }
    }
}

Describe 'Test-CRC32Match' -Tag 'Unit' {
    It 'matches the real 2026-08-02 App case: expected 404699 vs actual 00404699' {
        InModuleScope LoxoneUtils.Network {
            Test-CRC32Match -ActualCRC '00404699' -ExpectedCRC '404699' | Should -BeTrue
        }
    }

    It 'matches the previously-handled 7-char case (no regression)' {
        InModuleScope LoxoneUtils.Network {
            Test-CRC32Match -ActualCRC '0F415607' -ExpectedCRC 'f415607' | Should -BeTrue
        }
    }

    It 'matches identical canonical values regardless of case' {
        InModuleScope LoxoneUtils.Network {
            Test-CRC32Match -ActualCRC 'E487DD39' -ExpectedCRC 'e487dd39' | Should -BeTrue
        }
    }

    It 'still rejects genuinely different checksums' {
        InModuleScope LoxoneUtils.Network {
            Test-CRC32Match -ActualCRC '00404699' -ExpectedCRC '404698'   | Should -BeFalse
            Test-CRC32Match -ActualCRC 'DEADBEEF' -ExpectedCRC 'e487dd39' | Should -BeFalse
        }
    }

    It 'does not treat a zero-padded value as equal to a different-magnitude one' {
        InModuleScope LoxoneUtils.Network {
            # '4699' padded is 00004699 - must NOT equal 00404699
            Test-CRC32Match -ActualCRC '00404699' -ExpectedCRC '4699' | Should -BeFalse
        }
    }

    It 'falls back to string comparison when a value is not parseable hex' {
        InModuleScope LoxoneUtils.Network {
            Test-CRC32Match -ActualCRC 'notahex' -ExpectedCRC 'notahex' | Should -BeTrue
            Test-CRC32Match -ActualCRC 'notahex' -ExpectedCRC 'other'   | Should -BeFalse
        }
    }
}
