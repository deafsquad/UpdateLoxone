# Quick-win unit tests for pure utility functions:
#   Format-Bytes  (LoxoneUtils.Network.psm1)
#   Test-ExistingFile  (LoxoneUtils.Utility.psm1)
#   Get-CRC32  (LoxoneUtils.Utility.psm1)

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

    # Format-Bytes is defined inside LoxoneUtils.Network.psm1 but not in its
    # Export-ModuleMember list.  We invoke it through the module's internal scope.
    $script:LoxModule = Get-Module LoxoneUtils
    function script:Invoke-FormatBytes ([int64]$Bytes) {
        & $script:LoxModule { param($b) Format-Bytes -Bytes $b } $Bytes
    }

    # Set up log file for functions that need it
    $script:TestTempPath = Join-Path $TestDrive "UtilityTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Format-Bytes
# ---------------------------------------------------------------------------
Describe 'Format-Bytes' -Tag 'Unit' {

    It 'Returns "0 bytes" for zero input' {
        $result = Invoke-FormatBytes -Bytes 0
        $result | Should -BeExactly '0 bytes'
    }

    It 'Returns plain bytes for values below 1 KB' {
        $result = Invoke-FormatBytes -Bytes 512
        $result | Should -BeExactly '512 bytes'
    }

    It 'Returns 1 byte for a single byte' {
        $result = Invoke-FormatBytes -Bytes 1
        $result | Should -BeExactly '1 bytes'
    }

    It 'Formats values in the KB range' {
        # 1 KB = 1024 bytes
        $result = Invoke-FormatBytes -Bytes 1024
        $result | Should -Match '^\d+[\.,]\d{2} KB$'
        # 1024 bytes = 1.00 KB
        $result | Should -Match '^1[\.,]00 KB$'
    }

    It 'Formats values in the KB range with fractional part' {
        # 2560 bytes = 2.50 KB
        $result = Invoke-FormatBytes -Bytes 2560
        $result | Should -Match '^2[\.,]50 KB$'
    }

    It 'Formats values in the MB range' {
        # 1 MB = 1048576 bytes
        $result = Invoke-FormatBytes -Bytes 1048576
        $result | Should -Match '^\d+[\.,]\d{2} MB$'
        $result | Should -Match '^1[\.,]00 MB$'
    }

    It 'Formats values in the MB range with fractional part' {
        # 5.25 MB = 5505024 bytes
        $result = Invoke-FormatBytes -Bytes 5505024
        $result | Should -Match '^5[\.,]25 MB$'
    }

    It 'Formats values in the GB range' {
        # 1 GB = 1073741824 bytes
        $result = Invoke-FormatBytes -Bytes 1073741824
        $result | Should -Match '^\d+[\.,]\d{2} GB$'
        $result | Should -Match '^1[\.,]00 GB$'
    }

    It 'Formats values in the GB range with fractional part' {
        # 2.5 GB = 2684354560 bytes
        $result = Invoke-FormatBytes -Bytes 2684354560
        $result | Should -Match '^2[\.,]50 GB$'
    }

    It 'Returns MB for values just below 1 GB' {
        # 1 GB - 1 byte = 1073741823 bytes -> should still be in MB range
        $result = Invoke-FormatBytes -Bytes 1073741823
        $result | Should -Match 'MB$'
    }

    It 'Returns KB for values just below 1 MB' {
        # 1 MB - 1 byte = 1048575 bytes -> should still be in KB range
        $result = Invoke-FormatBytes -Bytes 1048575
        $result | Should -Match 'KB$'
    }
}

# ---------------------------------------------------------------------------
# Test-ExistingFile
# ---------------------------------------------------------------------------
Describe 'Test-ExistingFile' -Tag 'Unit' {

    BeforeAll {
        # Ensure CRC32 type is loaded for tests that use CRC validation
        Initialize-CRC32Type
    }

    Context 'Basic existence checks' {

        It 'Returns $true for a file that exists' {
            $filePath = Join-Path $script:TestTempPath 'exists.txt'
            Set-Content -Path $filePath -Value 'hello' -NoNewline
            $result = Test-ExistingFile -FilePath $filePath
            $result | Should -BeTrue
        }

        It 'Returns $false for a file that does not exist' {
            $filePath = Join-Path $script:TestTempPath 'nonexistent.txt'
            $result = Test-ExistingFile -FilePath $filePath
            $result | Should -BeFalse
        }

        It 'Returns $false for a directory path (uses -PathType Leaf)' {
            $dirPath = Join-Path $script:TestTempPath 'subdir'
            New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
            $result = Test-ExistingFile -FilePath $dirPath
            $result | Should -BeFalse
        }
    }

    Context 'Size validation' {

        It 'Returns $true when ExpectedSize matches actual size' {
            $filePath = Join-Path $script:TestTempPath 'sizecheck.bin'
            # Write exactly 100 bytes
            [System.IO.File]::WriteAllBytes($filePath, (New-Object byte[] 100))
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize 100
            $result | Should -BeTrue
        }

        It 'Returns $false when ExpectedSize does not match actual size' {
            $filePath = Join-Path $script:TestTempPath 'sizemismatch.bin'
            [System.IO.File]::WriteAllBytes($filePath, (New-Object byte[] 100))
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize 200
            $result | Should -BeFalse
        }

        It 'Skips size check when ExpectedSize is 0' {
            $filePath = Join-Path $script:TestTempPath 'sizezero.bin'
            [System.IO.File]::WriteAllBytes($filePath, (New-Object byte[] 50))
            # ExpectedSize of 0 should skip the check and still return true
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize 0
            $result | Should -BeTrue
        }
    }

    Context 'CRC validation' {

        It 'Returns $true when ExpectedCRC matches actual CRC' {
            $filePath = Join-Path $script:TestTempPath 'crcmatch.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('test content for crc')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            # Pre-compute the actual CRC so we can assert correctly
            $actualCRC = Get-CRC32 -InputFile $filePath
            $result = Test-ExistingFile -FilePath $filePath -ExpectedCRC $actualCRC -EnableCRC $true
            $result | Should -BeTrue
        }

        It 'Returns $false when ExpectedCRC does not match' {
            $filePath = Join-Path $script:TestTempPath 'crcfail.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('some data')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            $result = Test-ExistingFile -FilePath $filePath -ExpectedCRC 'DEADBEEF' -EnableCRC $true
            $result | Should -BeFalse
        }

        It 'Skips CRC check when EnableCRC is $false' {
            $filePath = Join-Path $script:TestTempPath 'crcskip.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('any data')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            # Pass a wrong CRC but disable CRC checking - should still pass
            $result = Test-ExistingFile -FilePath $filePath -ExpectedCRC 'WRONGCRC' -EnableCRC $false
            $result | Should -BeTrue
        }

        It 'Skips CRC check when ExpectedCRC is not provided' {
            $filePath = Join-Path $script:TestTempPath 'crcnoparam.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('no crc param')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            $result = Test-ExistingFile -FilePath $filePath -EnableCRC $true
            $result | Should -BeTrue
        }
    }

    Context 'Combined size and CRC validation' {

        It 'Returns $true when both size and CRC match' {
            $filePath = Join-Path $script:TestTempPath 'combined_ok.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('combined test data')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            $actualCRC = Get-CRC32 -InputFile $filePath
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize $content.Length -ExpectedCRC $actualCRC -EnableCRC $true
            $result | Should -BeTrue
        }

        It 'Returns $false when size matches but CRC does not' {
            $filePath = Join-Path $script:TestTempPath 'combined_crcfail.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('size ok crc bad')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize $content.Length -ExpectedCRC 'BADC0DE0' -EnableCRC $true
            $result | Should -BeFalse
        }

        It 'Returns $false when CRC matches but size does not' {
            $filePath = Join-Path $script:TestTempPath 'combined_sizefail.bin'
            $content = [System.Text.Encoding]::UTF8.GetBytes('crc ok size bad')
            [System.IO.File]::WriteAllBytes($filePath, $content)
            $actualCRC = Get-CRC32 -InputFile $filePath
            # Size check happens before CRC, so a wrong size should return false immediately
            $result = Test-ExistingFile -FilePath $filePath -ExpectedSize ($content.Length + 999) -ExpectedCRC $actualCRC -EnableCRC $true
            $result | Should -BeFalse
        }
    }
}

# ---------------------------------------------------------------------------
# Get-CRC32
# ---------------------------------------------------------------------------
Describe 'Get-CRC32' -Tag 'Unit' {

    BeforeAll {
        Initialize-CRC32Type
    }

    It 'Returns an 8-character uppercase hex string' {
        $filePath = Join-Path $script:TestTempPath 'crc_format.bin'
        [System.IO.File]::WriteAllBytes($filePath, [System.Text.Encoding]::UTF8.GetBytes('hex format test'))
        $result = Get-CRC32 -InputFile $filePath
        $result | Should -Match '^[0-9A-F]{8}$'
    }

    It 'Returns consistent results across multiple calls on the same file' {
        $filePath = Join-Path $script:TestTempPath 'crc_consistent.bin'
        [System.IO.File]::WriteAllBytes($filePath, [System.Text.Encoding]::UTF8.GetBytes('consistent content'))
        $first  = Get-CRC32 -InputFile $filePath
        $second = Get-CRC32 -InputFile $filePath
        $third  = Get-CRC32 -InputFile $filePath
        $first  | Should -BeExactly $second
        $second | Should -BeExactly $third
    }

    It 'Returns different checksums for different file contents' {
        $fileA = Join-Path $script:TestTempPath 'crc_a.bin'
        $fileB = Join-Path $script:TestTempPath 'crc_b.bin'
        [System.IO.File]::WriteAllBytes($fileA, [System.Text.Encoding]::UTF8.GetBytes('content A'))
        [System.IO.File]::WriteAllBytes($fileB, [System.Text.Encoding]::UTF8.GetBytes('content B'))
        $crcA = Get-CRC32 -InputFile $fileA
        $crcB = Get-CRC32 -InputFile $fileB
        $crcA | Should -Not -BeExactly $crcB
    }

    It 'Handles an empty file without error' {
        $filePath = Join-Path $script:TestTempPath 'crc_empty.bin'
        [System.IO.File]::WriteAllBytes($filePath, @())
        $result = Get-CRC32 -InputFile $filePath
        $result | Should -Match '^[0-9A-F]{8}$'
    }

    It 'Computes the well-known CRC32 for the ASCII string "123456789"' {
        # The standard CRC32 of the byte sequence 0x31..0x39 is CBF43926
        $filePath = Join-Path $script:TestTempPath 'crc_known.bin'
        [System.IO.File]::WriteAllBytes($filePath, [System.Text.Encoding]::ASCII.GetBytes('123456789'))
        $result = Get-CRC32 -InputFile $filePath
        $result | Should -BeExactly 'CBF43926'
    }

    It 'Throws when the input file does not exist' {
        $bogusPath = Join-Path $script:TestTempPath 'does_not_exist.bin'
        { Get-CRC32 -InputFile $bogusPath } | Should -Throw
    }
}
