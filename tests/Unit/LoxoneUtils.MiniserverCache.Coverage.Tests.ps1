# Coverage tests for LoxoneUtils.MiniserverCache - Update-MiniserverListCache
# Tests the file-based cache update logic with mocked filesystem

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

    $script:TestTempPath = Join-Path $TestDrive "CacheCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Update-MiniserverListCache" -Tag 'Unit', 'MiniserverCache' {

    BeforeEach {
        $script:CacheFile = Join-Path $script:TestTempPath "ms-list-$(Get-Random).txt"
    }

    Context "File not found" {

        It "Should warn and return when file does not exist" {
            $nonExistentPath = Join-Path $script:TestTempPath "no-such-file.txt"

            $warningOutput = Update-MiniserverListCache `
                -FilePath $nonExistentPath `
                -IP '10.0.0.1' `
                -Version '14.5.0.0' `
                3>&1

            $warningOutput | Should -Not -BeNullOrEmpty
            ($warningOutput | Out-String) | Should -Match 'not found'
        }
    }

    Context "Updating an existing entry" {

        It "Should update the line matching the target IP with version and timestamp" {
            $initialContent = @(
                '# Comment line',
                'http://admin:pass@192.168.1.10',
                'http://admin:pass@10.0.0.5'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            $fixedTimestamp = Get-Date -Year 2025 -Month 7 -Day 15 -Hour 10 -Minute 30 -Second 0

            Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '10.0.0.5' `
                -Version '14.6.0.0' `
                -Timestamp $fixedTimestamp

            $lines = Get-Content $script:CacheFile
            # Comment should be preserved
            $lines[0] | Should -Be '# Comment line'
            # First entry should be untouched
            $lines[1] | Should -Be 'http://admin:pass@192.168.1.10'
            # Updated entry should have version and timestamp
            $lines[2] | Should -Match '^http://admin:pass@10\.0\.0\.5,14\.6\.0\.0,20250715_103000$'
        }

        It "Should include generation field when Generation parameter is provided" {
            # Use multi-line file to avoid PowerShell single-line Get-Content string indexing
            $initialContent = @(
                '# Miniserver list',
                'http://admin:pass@10.0.0.5'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            $fixedTimestamp = Get-Date -Year 2025 -Month 8 -Day 1 -Hour 12 -Minute 0 -Second 0

            Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '10.0.0.5' `
                -Version '14.7.0.0' `
                -Generation 'Gen2' `
                -Timestamp $fixedTimestamp

            $lines = Get-Content $script:CacheFile
            $lines[0] | Should -Be '# Miniserver list'
            $lines[1] | Should -Match '^http://admin:pass@10\.0\.0\.5,14\.7\.0\.0,20250801_120000,Gen2$'
        }

        It "Should preserve existing generation when no Generation parameter is given but line had one" {
            # Use multi-line file to avoid PowerShell single-line Get-Content string indexing
            $initialContent = @(
                '# Miniserver list',
                'http://admin:pass@10.0.0.5,14.5.0.0,20250601_100000,Gen1-Green'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            $fixedTimestamp = Get-Date -Year 2025 -Month 9 -Day 1 -Hour 8 -Minute 0 -Second 0

            Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '10.0.0.5' `
                -Version '14.8.0.0' `
                -Timestamp $fixedTimestamp

            $lines = Get-Content $script:CacheFile
            $lines[1] | Should -Match 'Gen1-Green'
        }
    }

    Context "Entry not found" {

        It "Should warn when the target IP is not in the file" {
            # Use multi-line file to avoid PowerShell single-line Get-Content string indexing
            $initialContent = @(
                '# Miniserver list',
                'http://admin:pass@192.168.1.10'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            $warningOutput = Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '99.99.99.99' `
                -Version '14.5.0.0' `
                3>&1

            $warningOutput | Should -Not -BeNullOrEmpty
            ($warningOutput | Out-String) | Should -Match 'Could not find'
        }

        It "Should not modify the file when the IP is not found" {
            # Use multi-line file to avoid PowerShell single-line Get-Content string indexing
            $initialContent = @(
                '# Miniserver list',
                'http://admin:pass@192.168.1.10'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '99.99.99.99' `
                -Version '14.5.0.0' `
                3>$null

            $lines = Get-Content $script:CacheFile
            $lines[1] | Should -Be 'http://admin:pass@192.168.1.10'
        }
    }

    Context "Comments and empty lines" {

        It "Should skip comment lines and empty lines without modifying them" {
            $initialContent = @(
                '# Header comment',
                '',
                'http://admin:pass@10.0.0.1',
                '# Another comment',
                'http://admin:pass@10.0.0.2'
            )
            Set-Content -Path $script:CacheFile -Value $initialContent -Encoding UTF8

            $fixedTimestamp = Get-Date -Year 2025 -Month 6 -Day 15 -Hour 9 -Minute 0 -Second 0

            Update-MiniserverListCache `
                -FilePath $script:CacheFile `
                -IP '10.0.0.2' `
                -Version '14.5.0.0' `
                -Timestamp $fixedTimestamp

            $lines = Get-Content $script:CacheFile
            $lines[0] | Should -Be '# Header comment'
            $lines[1] | Should -BeNullOrEmpty
            $lines[2] | Should -Be 'http://admin:pass@10.0.0.1'
            $lines[3] | Should -Be '# Another comment'
            $lines[4] | Should -Match '10\.0\.0\.2,14\.5\.0\.0'
        }
    }

    Context "Parameter validation" {

        It "Should accept mandatory FilePath, IP, and Version parameters" {
            $cmd = Get-Command Update-MiniserverListCache
            $cmd.Parameters['FilePath'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
            $cmd.Parameters['IP'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
            $cmd.Parameters['Version'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
        }
    }
}
