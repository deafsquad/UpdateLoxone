# Simple test to verify mock loading works
Describe "Mock Loading Verification" {
    BeforeAll {
        # Get paths
        $testRoot = Split-Path -Parent $PSScriptRoot
        $projectRoot = Split-Path -Parent $testRoot
        $moduleRoot = Join-Path $projectRoot "LoxoneUtils"
        
        # Import module
        $modulePath = Join-Path $moduleRoot "LoxoneUtils.psd1"
        Import-Module $modulePath -Force
        
        # Set test flags
        $env:PESTER_TEST_RUN = '1'
        $env:LOXONE_TEST_MODE = '1'
        $Global:IsTestRun = $true
    }
    
    Context "Network Mocks" {
        BeforeAll {
            $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.Network.TestMocks.ps1"
            . $mockPath
        }
        
        It "Should load Network mocks" {
            $Global:NetworkMocksLoaded | Should -Be $true
        }
        
        It "Should mock Invoke-LoxoneDownload" {
            $result = Invoke-LoxoneDownload -Url "http://test.com" -DestinationPath "C:\temp\test.zip" -ActivityName "Test Download"
            $result | Should -Not -BeNullOrEmpty
            $result.Succeeded | Should -Be $true
        }
    }
    
    Context "Installation Mocks" {
        BeforeAll {
            $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.Installation.TestMocks.ps1"
            . $mockPath
        }
        
        It "Should load Installation mocks" {
            $Global:InstallationMocksLoaded | Should -Be $true
        }
        
        It "Should mock Get-InstalledVersion" {
            $version = Get-InstalledVersion -ExePath "C:\fake\path.exe"
            $version | Should -Be "14.0.0.0"
        }
        
        It "Should mock Start-LoxoneUpdateInstaller" {
            $result = Start-LoxoneUpdateInstaller -InstallerPath "C:\fake\installer.msi"
            $result | Should -Not -BeNullOrEmpty
            $result.Success | Should -Be $true
        }
    }
    
    Context "Miniserver Mocks" {
        BeforeAll {
            $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.Miniserver.TestMocks.ps1"
            . $mockPath
        }
        
        It "Should load Miniserver mocks" {
            $Global:MiniserverMocksLoaded | Should -Be $true
        }
        
        It "Should mock Get-MiniserverVersion" {
            $version = Get-MiniserverVersion -MSEntry "http://192.168.1.100"
            $version | Should -BeOfType [version]
            $version.ToString() | Should -Be "14.0.0.0"
        }
        
        It "Should mock Invoke-MSUpdate" {
            $result = Invoke-MSUpdate -MSUri "http://192.168.1.100" -NormalizedDesiredVersion "14.0.0.0" -Credential $null
            $result | Should -Not -BeNullOrEmpty
            $result.Succeeded | Should -Be $true
        }
    }
    
    Context "Logging Mocks" {
        BeforeAll {
            $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.Logging.TestMocks.ps1"
            . $mockPath
        }
        
        It "Should load Logging mocks" {
            $Global:LoggingMocksLoaded | Should -Be $true
        }
        
        It "Should have a test log file" {
            $Global:LogFile | Should -Not -BeNullOrEmpty
            Test-Path $Global:LogFile | Should -Be $true
        }
        
        It "Should mock Invoke-LogFileRotation" {
            $result = Invoke-LogFileRotation -LogFilePath $Global:LogFile
            $result | Should -Be $false
        }
    }
    
    Context "System Mocks" {
        BeforeAll {
            $mockPath = Join-Path $PSScriptRoot "LoxoneUtils.System.TestMocks.ps1"
            . $mockPath
        }
        
        It "Should load System mocks" {
            # Skip in parallel mode - mocks are loaded differently
            if ($env:PARALLEL_TEST_EXECUTION -eq "1" -or $env:LOXONE_PARALLEL_MODE -eq "1") {
                Set-ItResult -Skipped -Because "Mock loading tests don't work in parallel mode"
                return
            }
            $Global:SystemMocksLoaded | Should -Be $true
        }
        
        It "Should mock Get-ProcessStatus" {
            # Skip in parallel mode - mocks are loaded differently
            if ($env:PARALLEL_TEST_EXECUTION -eq "1" -or $env:LOXONE_PARALLEL_MODE -eq "1") {
                Set-ItResult -Skipped -Because "Mock loading tests don't work in parallel mode"
                return
            }
            $status = Get-ProcessStatus -ProcessName "LoxoneConfig"
            $status | Should -Not -BeNullOrEmpty
            $status.ConfigRunning | Should -Be $false
            $status.MonitorRunning | Should -Be $false
        }
        
        It "Should mock Test-LoxoneScheduledTaskExists" {
            # Skip in parallel mode - mocks are loaded differently
            if ($env:PARALLEL_TEST_EXECUTION -eq "1" -or $env:LOXONE_PARALLEL_MODE -eq "1") {
                Set-ItResult -Skipped -Because "Mock loading tests don't work in parallel mode"
                return
            }
            $exists = Test-LoxoneScheduledTaskExists -TaskName "TestTask"
            $exists | Should -Be $false
        }
    }
}