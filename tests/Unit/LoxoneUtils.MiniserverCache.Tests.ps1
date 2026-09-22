# Unit tests for LoxoneUtils.MiniserverCache
# Tests ConvertFrom-MiniserverListEntry and Test-MiniserverCacheValid

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
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "ConvertFrom-MiniserverListEntry" -Tag 'Unit' {

    Context "Valid entries" {

        It "Should parse a plain URL entry and extract the IP" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://admin:secret@192.168.1.10'

            $result | Should -Not -BeNullOrEmpty
            $result.Url | Should -Be 'http://admin:secret@192.168.1.10'
            $result.IP  | Should -Be '192.168.1.10'
            $result.HasCache | Should -Be $false
            $result.CachedVersion | Should -BeNullOrEmpty
            $result.LastChecked | Should -BeNullOrEmpty
        }

        It "Should parse an entry with cached version" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://admin:pass@10.0.0.5,14.5.12.3'

            $result.Url | Should -Be 'http://admin:pass@10.0.0.5'
            $result.IP  | Should -Be '10.0.0.5'
            $result.CachedVersion | Should -Be '14.5.12.3'
            $result.HasCache | Should -Be $true
            $result.LastChecked | Should -BeNullOrEmpty
        }

        It "Should parse an entry with cached version and timestamp" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://user:pw@172.16.0.1,14.5.12.3,20250601_143000'

            $result.Url | Should -Be 'http://user:pw@172.16.0.1'
            $result.IP  | Should -Be '172.16.0.1'
            $result.CachedVersion | Should -Be '14.5.12.3'
            $result.HasCache | Should -Be $true
            $result.LastChecked | Should -Not -BeNullOrEmpty
            $result.LastChecked.Year   | Should -Be 2025
            $result.LastChecked.Month  | Should -Be 6
            $result.LastChecked.Day    | Should -Be 1
            $result.LastChecked.Hour   | Should -Be 14
            $result.LastChecked.Minute | Should -Be 30
            $result.LastChecked.Second | Should -Be 0
        }

        It "Should parse an entry with generation info" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://user:pw@10.0.0.1,14.5.12.3,20250601_120000,Gen2'

            $result.Generation | Should -Be 'Gen2'
            $result.CachedVersion | Should -Be '14.5.12.3'
            $result.HasCache | Should -Be $true
        }

        It "Should parse an entry with generation and generation timestamp" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://user:pw@10.0.0.1,14.5.12.3,20250601_120000,Gen2,20250602_080000'

            $result.Generation | Should -Be 'Gen2'
            $result.GenerationLastChecked | Should -Not -BeNullOrEmpty
            $result.GenerationLastChecked.Year  | Should -Be 2025
            $result.GenerationLastChecked.Month | Should -Be 6
            $result.GenerationLastChecked.Day   | Should -Be 2
            $result.GenerationLastChecked.Hour  | Should -Be 8
        }

        It "Should handle URL with port number and still extract IP" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://admin:pass@192.168.0.77:8080'

            $result.IP | Should -Be '192.168.0.77'
            $result.Url | Should -Be 'http://admin:pass@192.168.0.77:8080'
        }

        It "Should trim whitespace from parts" {
            $result = ConvertFrom-MiniserverListEntry -Line '  http://admin:pass@10.0.0.9 , 14.0.0.0 , 20250101_000000 '

            $result.Url | Should -Be 'http://admin:pass@10.0.0.9'
            $result.CachedVersion | Should -Be '14.0.0.0'
            $result.HasCache | Should -Be $true
            $result.LastChecked | Should -Not -BeNullOrEmpty
        }
    }

    Context "Invalid and edge-case entries" {

        It "Should return null for an empty string" {
            $result = ConvertFrom-MiniserverListEntry -Line ''
            $result | Should -BeNullOrEmpty
        }

        It "Should return null for a whitespace-only string" {
            $result = ConvertFrom-MiniserverListEntry -Line '   '
            $result | Should -BeNullOrEmpty
        }

        It "Should return null for a comment line" {
            $result = ConvertFrom-MiniserverListEntry -Line '# This is a comment'
            $result | Should -BeNullOrEmpty
        }

        It "Should return null for a comment line with leading spaces" {
            $result = ConvertFrom-MiniserverListEntry -Line '  # Also a comment'
            $result | Should -BeNullOrEmpty
        }

        It "Should handle an entry with empty version field gracefully" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://admin:pass@10.0.0.1,,'

            $result | Should -Not -BeNullOrEmpty
            $result.HasCache | Should -Be $false
            $result.CachedVersion | Should -BeNullOrEmpty
        }

        It "Should handle a malformed timestamp without crashing" {
            $result = ConvertFrom-MiniserverListEntry -Line 'http://admin:pass@10.0.0.1,14.0.0.0,BADTIMESTAMP'

            $result | Should -Not -BeNullOrEmpty
            $result.CachedVersion | Should -Be '14.0.0.0'
            $result.HasCache | Should -Be $true
            $result.LastChecked | Should -BeNullOrEmpty
        }
    }
}

Describe "Test-MiniserverCacheValid" -Tag 'Unit' {

    Context "No cache available" {

        It "Should return false when HasCache is false" {
            $entry = @{
                HasCache      = $false
                CachedVersion = $null
                LastChecked   = $null
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $false
        }

        It "Should return false when CachedVersion is null even if HasCache is true" {
            $entry = @{
                HasCache      = $true
                CachedVersion = $null
                LastChecked   = Get-Date
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $false
        }
    }

    Context "Version matching" {

        It "Should return false when TargetVersion does not match CachedVersion" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(-1)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry -TargetVersion '14.6.0.0'
            $result | Should -Be $false
        }

        It "Should accept cache when TargetVersion matches CachedVersion and cache is fresh" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(-1)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry -TargetVersion '14.5.0.0'
            $result | Should -Be $true
        }

        It "Should skip version comparison when TargetVersion is not provided" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddMinutes(-30)
                IP            = '10.0.0.1'
            }

            # No TargetVersion - should only check cache age
            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $true
        }

        It "Should skip version comparison when TargetVersion is empty string" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddMinutes(-30)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry -TargetVersion ''
            $result | Should -Be $true
        }
    }

    Context "Cache age" {

        It "Should return false when cache is older than MaxCacheAgeHours" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(-25)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry -MaxCacheAgeHours 24
            $result | Should -Be $false
        }

        It "Should return true when cache is within MaxCacheAgeHours" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(-12)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry -MaxCacheAgeHours 24
            $result | Should -Be $true
        }

        It "Should respect custom MaxCacheAgeHours value" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(-3)
                IP            = '10.0.0.1'
            }

            # 2-hour max: cache at 3 hours old should be invalid
            $result = Test-MiniserverCacheValid -MSEntry $entry -MaxCacheAgeHours 2
            $result | Should -Be $false
        }

        It "Should return true for a very recently created cache" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddSeconds(-10)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $true
        }
    }

    Context "Missing timestamp" {

        It "Should return false when LastChecked is null (conservative behavior)" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = $null
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $false
        }
    }

    Context "Future timestamps" {

        It "Should return false for a timestamp far in the future" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                LastChecked   = (Get-Date).AddHours(2)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $false
        }

        It "Should accept a timestamp only slightly in the future (clock skew tolerance)" {
            $entry = @{
                HasCache      = $true
                CachedVersion = '14.5.0.0'
                # 30 seconds in the future - within the 1-minute tolerance
                LastChecked   = (Get-Date).AddSeconds(30)
                IP            = '10.0.0.1'
            }

            $result = Test-MiniserverCacheValid -MSEntry $entry
            $result | Should -Be $true
        }
    }

    Context "Integration: parsed entry fed into cache validation" {

        It "Should validate a freshly parsed entry with full cache data as valid" {
            $now = Get-Date
            $timestampStr = $now.AddHours(-2).ToString('yyyyMMdd_HHmmss')
            $line = "http://admin:pass@10.0.0.50,14.5.12.3,$timestampStr"

            $entry = ConvertFrom-MiniserverListEntry -Line $line
            $result = Test-MiniserverCacheValid -MSEntry $entry -TargetVersion '14.5.12.3' -MaxCacheAgeHours 24

            $result | Should -Be $true
        }

        It "Should reject a parsed entry whose cache is expired" {
            $old = (Get-Date).AddHours(-48)
            $timestampStr = $old.ToString('yyyyMMdd_HHmmss')
            $line = "http://admin:pass@10.0.0.50,14.5.12.3,$timestampStr"

            $entry = ConvertFrom-MiniserverListEntry -Line $line
            $result = Test-MiniserverCacheValid -MSEntry $entry -MaxCacheAgeHours 24

            $result | Should -Be $false
        }

        It "Should reject a parsed entry with no cache fields" {
            $line = 'http://admin:pass@10.0.0.50'

            $entry = ConvertFrom-MiniserverListEntry -Line $line
            $result = Test-MiniserverCacheValid -MSEntry $entry

            $result | Should -Be $false
        }
    }
}
