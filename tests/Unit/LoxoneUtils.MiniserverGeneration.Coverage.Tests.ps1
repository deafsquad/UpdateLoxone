# Coverage tests for LoxoneUtils.MiniserverGeneration - Update-MiniserverGenerationCache
# Tests generation cache update logic with mocked network and filesystem

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

    $script:TestTempPath = Join-Path $TestDrive "GenCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Update-MiniserverGenerationCache" -Tag 'Unit', 'MiniserverGeneration' {

    Context "Function availability" {

        It "Should be available as an exported function" {
            $cmd = Get-Command Update-MiniserverGenerationCache -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
        }

        It "Should have mandatory FilePath parameter" {
            $cmd = Get-Command Update-MiniserverGenerationCache
            $cmd.Parameters['FilePath'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
        }

        It "Should have mandatory MSEntry parameter" {
            $cmd = Get-Command Update-MiniserverGenerationCache
            $cmd.Parameters['MSEntry'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory | Should -Be $true }
        }
    }

    Context "Entry not in cache" {

        It "Should not modify file when MS entry is not found" {
            $cacheFile = Join-Path $script:TestTempPath "gen-notfound-$(Get-Random).txt"
            $content = @(
                '# Miniserver list',
                'http://admin:pass@192.168.1.10,14.5.0.0,20250601_120000'
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            # Pass a URL not in the file - function logs warning internally
            Update-MiniserverGenerationCache -FilePath $cacheFile -MSEntry 'http://admin:pass@99.99.99.99'

            # File should be unchanged
            $lines = Get-Content $cacheFile
            $lines[1] | Should -Match '192\.168\.1\.10'
            $lines[1] | Should -Not -Match 'Gen'
        }
    }

    Context "Generation detection via InModuleScope" {

        It "Should call Get-MiniserverGenerationInfo when no generation exists in cache" {
            $cacheFile = Join-Path $script:TestTempPath "gen-detect-$(Get-Random).txt"
            $content = @(
                '# Miniserver list',
                'http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000'
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{
                        Generation = "Gen2"
                        Description = "Generation 2 - Latest Hardware (Type 2)"
                        RequiresHTTPS = $true
                        DetectionMethod = "Status-Type2"
                        Success = $true
                        Error = $null
                    }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5'

                Should -Invoke Get-MiniserverGenerationInfo -Times 1
            }

            $lines = Get-Content $cacheFile
            $lines[1] | Should -Match 'Gen2'
        }

        It "Should skip detection when generation was checked recently" {
            $cacheFile = Join-Path $script:TestTempPath "gen-recent-$(Get-Random).txt"
            $recentTimestamp = (Get-Date).AddDays(-1).ToString('yyyyMMdd_HHmmss')
            $content = @(
                '# Miniserver list',
                "http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000,Gen1-Green,$recentTimestamp"
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{ Generation = "Gen2"; Success = $true; Error = $null }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5'

                Should -Invoke Get-MiniserverGenerationInfo -Times 0
            }
        }

        It "Should refresh generation when check is older than 7 days" {
            $cacheFile = Join-Path $script:TestTempPath "gen-stale-$(Get-Random).txt"
            $oldTimestamp = (Get-Date).AddDays(-10).ToString('yyyyMMdd_HHmmss')
            $content = @(
                '# Miniserver list',
                "http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000,Gen1-Grey,$oldTimestamp"
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{
                        Generation = "Gen2"
                        Description = "Generation 2"
                        RequiresHTTPS = $true
                        DetectionMethod = "Status-Type2"
                        Success = $true
                        Error = $null
                    }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5'

                Should -Invoke Get-MiniserverGenerationInfo -Times 1
            }

            $lines = Get-Content $cacheFile
            $lines[1] | Should -Match 'Gen2'
        }

        It "Should force detection even when generation is current" {
            $cacheFile = Join-Path $script:TestTempPath "gen-force-$(Get-Random).txt"
            $recentTimestamp = (Get-Date).AddDays(-1).ToString('yyyyMMdd_HHmmss')
            $content = @(
                '# Miniserver list',
                "http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000,Gen1-Green,$recentTimestamp"
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{
                        Generation = "Gen2"
                        Description = "Generation 2"
                        RequiresHTTPS = $true
                        DetectionMethod = "Status-Type2"
                        Success = $true
                        Error = $null
                    }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5' -ForceRefresh

                Should -Invoke Get-MiniserverGenerationInfo -Times 1
            }
        }

        It "Should not modify cache when detection fails" {
            $cacheFile = Join-Path $script:TestTempPath "gen-fail-$(Get-Random).txt"
            $content = @(
                '# Miniserver list',
                'http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000'
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{
                        Generation = "Unknown"
                        Description = "Unknown"
                        RequiresHTTPS = $false
                        DetectionMethod = "Unknown"
                        Success = $false
                        Error = "Connection refused"
                    }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5'
            }

            $lines = Get-Content $cacheFile
            $lines[1] | Should -Not -Match 'Gen2'
            $lines[1] | Should -Not -Match 'Unknown'
        }
    }

    Context "Comment preservation" {

        It "Should preserve comments and other entries when updating a specific entry" {
            $cacheFile = Join-Path $script:TestTempPath "gen-comments-$(Get-Random).txt"
            $content = @(
                '# Miniserver list',
                'http://admin:pass@192.168.1.10,14.5.0.0,20250601_120000,Gen1-Grey,20250601_120000',
                'http://admin:pass@10.0.0.5,14.5.0.0,20250601_120000'
            )
            Set-Content -Path $cacheFile -Value $content -Encoding UTF8

            InModuleScope LoxoneUtils.MiniserverGeneration -Parameters @{ CacheFile = $cacheFile } {
                param($CacheFile)
                Mock Write-Log {}

                Mock Get-MiniserverGenerationInfo {
                    return @{
                        Generation = "Gen2"
                        Description = "Generation 2"
                        RequiresHTTPS = $true
                        DetectionMethod = "Status-Type2"
                        Success = $true
                        Error = $null
                    }
                }

                Update-MiniserverGenerationCache -FilePath $CacheFile -MSEntry 'http://admin:pass@10.0.0.5'
            }

            $lines = Get-Content $cacheFile
            $lines[0] | Should -Be '# Miniserver list'
            $lines[1] | Should -Match 'Gen1-Grey'
            $lines[2] | Should -Match 'Gen2'
        }
    }
}
