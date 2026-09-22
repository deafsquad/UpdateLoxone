# Coverage tests for 8 untested exported functions in LoxoneUtils.WorkflowSteps

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
    $script:TestTempPath = Join-Path $TestDrive "WorkflowStepsCoverageTests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}
AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

# ============================================================================
# 1. Get-LoxoneUpdatePrerequisites
# ============================================================================
Describe "Get-LoxoneUpdatePrerequisites" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Get-LoxoneUpdatePrerequisites -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has the expected WorkflowContext parameter" {
            $cmd = Get-Command Get-LoxoneUpdatePrerequisites -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
        }
    }

    Context "Functional - returns prerequisite data from update check" {
        It "Returns a result object with expected properties when update data is available" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Get-LoxoneUpdateData {
                    return [PSCustomObject]@{
                        Error                  = $null
                        ConfigLatestVersion    = "14.1.2.3"
                        ConfigZipUrl           = "https://update.loxone.com/config.zip"
                        ConfigExpectedZipSize  = 50000000
                        ConfigExpectedCRC      = "AABB1122"
                        ConfigInstallerFileName = "LoxoneConfigSetup.exe"
                        ConfigZipFileName      = "LoxoneConfig.zip"
                        AppLatestVersion       = "14.1.2.3"
                        AppLatestVersionRaw    = "14.1.2.3"
                        AppInstallerUrl        = "https://update.loxone.com/app.exe"
                        AppExpectedSize        = 30000000
                        AppExpectedCRC         = "CCDD3344"
                        AppInstallerFileName   = "LoxoneWindowsSetup.exe"
                        SelectedAppChannelName = "Release"
                    }
                }
                Mock Convert-VersionString { param([string]$VersionString) return $VersionString }
                Mock Enter-Function {}
                Mock Exit-Function {}

                $workflowContext = [PSCustomObject]@{
                    Constants = [PSCustomObject]@{
                        UpdateXmlUrl      = "https://update.loxone.com/updatecheck.xml"
                        InstallerFileName = "LoxoneConfigSetup.exe"
                        ZipFileName       = "LoxoneConfig.zip"
                    }
                    Params = @{
                        Channel          = "Test"
                        UpdateLoxoneApp  = $true
                        EnableCRC        = $true
                    }
                    InitialInstalledConfigVersion = "14.0.0.0"
                    InitialLoxoneAppDetails = [PSCustomObject]@{
                        FileVersion       = "14.0.0.0"
                        ComparableVersion = $null
                        DisplayVersion    = "14.0.0.0"
                    }
                }

                $result = Get-LoxoneUpdatePrerequisites -WorkflowContext $workflowContext

                $result | Should -Not -BeNullOrEmpty
                $result.Succeeded | Should -Be $true
                $result.PSObject.Properties.Name | Should -Contain 'ConfigUpdateNeeded'
                $result.PSObject.Properties.Name | Should -Contain 'AppUpdateNeeded'
                $result.PSObject.Properties.Name | Should -Contain 'LatestConfigVersion'
                $result.PSObject.Properties.Name | Should -Contain 'LatestAppVersion'
                $result.PSObject.Properties.Name | Should -Contain 'ConfigZipUrl'
                $result.PSObject.Properties.Name | Should -Contain 'AppInstallerUrl'
                $result.LatestConfigVersion | Should -Be "14.1.2.3"
                $result.ConfigZipUrl | Should -Be "https://update.loxone.com/config.zip"
            }
        }

        It "Sets ConfigUpdateNeeded to true when newer version is available" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Get-LoxoneUpdateData {
                    return [PSCustomObject]@{
                        Error                  = $null
                        ConfigLatestVersion    = "15.0.0.0"
                        ConfigZipUrl           = "https://update.loxone.com/config.zip"
                        ConfigExpectedZipSize  = 50000000
                        ConfigExpectedCRC      = "AABB1122"
                        ConfigInstallerFileName = $null
                        ConfigZipFileName      = $null
                        AppLatestVersion       = $null
                        AppLatestVersionRaw    = $null
                        AppInstallerUrl        = $null
                        AppExpectedSize        = $null
                        AppExpectedCRC         = $null
                        AppInstallerFileName   = $null
                        SelectedAppChannelName = $null
                    }
                }
                Mock Convert-VersionString { param([string]$VersionString) return $VersionString }
                Mock Enter-Function {}
                Mock Exit-Function {}

                $workflowContext = [PSCustomObject]@{
                    Constants = [PSCustomObject]@{
                        UpdateXmlUrl      = "https://update.loxone.com/updatecheck.xml"
                        InstallerFileName = "LoxoneConfigSetup.exe"
                        ZipFileName       = "LoxoneConfig.zip"
                    }
                    Params = @{
                        Channel         = "Test"
                        UpdateLoxoneApp = $false
                    }
                    InitialInstalledConfigVersion = "14.0.0.0"
                    InitialLoxoneAppDetails = [PSCustomObject]@{
                        FileVersion       = "14.0.0.0"
                        ComparableVersion = $null
                        DisplayVersion    = "14.0.0.0"
                    }
                }

                $result = Get-LoxoneUpdatePrerequisites -WorkflowContext $workflowContext

                $result.Succeeded | Should -Be $true
                $result.ConfigUpdateNeeded | Should -Be $true
            }
        }

        It "Sets Succeeded to false when Get-LoxoneUpdateData returns error" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Get-LoxoneUpdateData {
                    return [PSCustomObject]@{
                        Error = "Connection failed"
                        ConfigLatestVersion = $null
                        AppLatestVersion    = $null
                    }
                }
                Mock Convert-VersionString { param([string]$VersionString) return $VersionString }
                Mock Enter-Function {}
                Mock Exit-Function {}

                $workflowContext = [PSCustomObject]@{
                    Constants = [PSCustomObject]@{
                        UpdateXmlUrl      = "https://update.loxone.com/updatecheck.xml"
                        InstallerFileName = "LoxoneConfigSetup.exe"
                        ZipFileName       = "LoxoneConfig.zip"
                    }
                    Params = @{ Channel = "Test" }
                    InitialInstalledConfigVersion = "14.0.0.0"
                    InitialLoxoneAppDetails = [PSCustomObject]@{
                        FileVersion = "14.0.0.0"
                    }
                }

                $result = Get-LoxoneUpdatePrerequisites -WorkflowContext $workflowContext

                $result.Succeeded | Should -Be $false
                $result.Reason | Should -Be "GetPrerequisitesFailed"
            }
        }
    }
}

# ============================================================================
# 2. Invoke-DownloadLoxoneConfig
# ============================================================================
Describe "Invoke-DownloadLoxoneConfig" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-DownloadLoxoneConfig -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-DownloadLoxoneConfig -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'ConfigTargetInfo'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ProgressReporter'
        }
    }

    Context "Functional - skip download when existing file is valid" {
        It "Skips download and returns DownloadSkipped when ZIP already exists and is valid" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Test-ExistingFile { return $true }
                Mock Get-StepWeight { return 10 }
                Mock Invoke-LoxoneDownload {}
                Mock Test-Path { return $true } -ParameterFilter { $Path -and $Path -like '*.zip' }

                $workflowContext = [PSCustomObject]@{
                    DownloadDir   = "C:\TestDownloads"
                    IsInteractive = $false
                    Params        = @{ EnableCRC = $true }
                }
                $configTargetInfo = [PSCustomObject]@{
                    ZipFilePath           = "C:\TestDownloads\LoxoneConfig.zip"
                    ExpectedCRC           = "AABB1122"
                    ExpectedSize          = 50000000
                    ZipFileName           = "LoxoneConfig.zip"
                    ExpectedInstallerName = "LoxoneConfigSetup.exe"
                }
                $globalState = @{
                    CurrentWeight   = 0
                    TotalWeight     = 100
                    currentStep     = 0
                    totalSteps      = 5
                    currentDownload = 0
                    totalDownloads  = 2
                    ErrorOccurred   = $false
                    anyUpdatePerformed = $false
                }

                $result = Invoke-DownloadLoxoneConfig -WorkflowContext $workflowContext `
                    -ConfigTargetInfo $configTargetInfo `
                    -ScriptGlobalState ([ref]$globalState)

                $result.Succeeded | Should -Be $true
                $result.DownloadSkipped | Should -Be $true
                $result.Component | Should -Be "Config"
                $result.Action | Should -Be "Download"
                Should -Invoke Invoke-LoxoneDownload -Times 0
            }
        }
    }
}

# ============================================================================
# 3. Invoke-ExtractLoxoneConfig
# ============================================================================
Describe "Invoke-ExtractLoxoneConfig" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-ExtractLoxoneConfig -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-ExtractLoxoneConfig -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'ConfigTargetInfo'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ProgressReporter'
        }
    }

    Context "Functional - extraction flow" {
        It "Extracts ZIP and verifies installer signature on success" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Test-Path { return $true } -ParameterFilter { $Path -like '*.zip' -and $PathType -eq 'Leaf' }
                Mock Test-Path { return $false } -ParameterFilter { $Path -like '*.exe' }
                Mock Expand-Archive {}
                Mock Get-ExecutableSignature {
                    return [PSCustomObject]@{
                        IsValid = $true
                        Subject = "CN=Loxone Electronics GmbH"
                    }
                }
                Mock Get-StepWeight { return 5 }
                Mock Update-PersistentToast {}
                Mock Remove-Item {}

                $workflowContext = [PSCustomObject]@{
                    DownloadDir   = "C:\TestDownloads"
                    LogDir        = "C:\TestLogs"
                    IsInteractive = $false
                    IsSelfInvokedForUpdateCheck = $false
                    Params        = @{}
                }
                $configTargetInfo = [PSCustomObject]@{
                    ZipFilePath           = "C:\TestDownloads\LoxoneConfig.zip"
                    InstallerPath         = "C:\TestDownloads\LoxoneConfigSetup.exe"
                    ExpectedInstallerName = "LoxoneConfigSetup.exe"
                }
                $globalState = @{
                    CurrentWeight      = 10
                    TotalWeight        = 100
                    currentStep        = 1
                    totalSteps         = 5
                    ErrorOccurred      = $false
                    anyUpdatePerformed = $false
                }

                $result = Invoke-ExtractLoxoneConfig -WorkflowContext $workflowContext `
                    -ConfigTargetInfo $configTargetInfo `
                    -ScriptGlobalState ([ref]$globalState)

                $result | Should -Not -BeNullOrEmpty
                $result.Component | Should -Be "Config"
                $result.Action | Should -Be "Extract"
                Should -Invoke Expand-Archive -Times 1
            }
        }

        It "Fails when ZIP file does not exist" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Test-Path { return $false }
                Mock Expand-Archive {}
                Mock Get-StepWeight { return 5 }

                $workflowContext = [PSCustomObject]@{
                    DownloadDir   = "C:\TestDownloads"
                    LogDir        = "C:\TestLogs"
                    IsInteractive = $false
                    Params        = @{}
                }
                $configTargetInfo = [PSCustomObject]@{
                    ZipFilePath           = "C:\TestDownloads\NonExistent.zip"
                    InstallerPath         = "C:\TestDownloads\LoxoneConfigSetup.exe"
                    ExpectedInstallerName = "LoxoneConfigSetup.exe"
                }
                $globalState = @{
                    CurrentWeight      = 10
                    TotalWeight        = 100
                    currentStep        = 1
                    totalSteps         = 5
                    ErrorOccurred      = $false
                    anyUpdatePerformed = $false
                }

                $result = Invoke-ExtractLoxoneConfig -WorkflowContext $workflowContext `
                    -ConfigTargetInfo $configTargetInfo `
                    -ScriptGlobalState ([ref]$globalState)

                $result.Succeeded | Should -Be $false
            }
        }
    }
}

# ============================================================================
# 4. Invoke-DownloadLoxoneApp
# ============================================================================
Describe "Invoke-DownloadLoxoneApp" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-DownloadLoxoneApp -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-DownloadLoxoneApp -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'AppTargetInfo'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ProgressReporter'
        }
    }

    Context "Functional - skip download when existing installer is valid" {
        It "Skips download and returns DownloadSkipped when valid installer exists" {
            InModuleScope LoxoneUtils.WorkflowSteps {
                Mock Write-Log {}
                Mock Test-ExistingInstaller {
                    return [PSCustomObject]@{
                        IsValid = $true
                        Reason  = "ValidInstaller"
                    }
                }
                Mock Get-StepWeight { return 10 }
                Mock Invoke-LoxoneDownload {}

                $workflowContext = [PSCustomObject]@{
                    DownloadDir   = "C:\TestDownloads"
                    IsInteractive = $false
                    Params        = @{}
                }
                $appTargetInfo = [PSCustomObject]@{
                    InstallerFileName = "LoxoneWindowsSetup.exe"
                    DownloadUrl       = "https://update.loxone.com/app.exe"
                    TargetVersion     = "14.1.2.3"
                    ExpectedSize      = 30000000
                    ExpectedCRC       = "CCDD3344"
                }
                $globalState = @{
                    CurrentWeight      = 20
                    TotalWeight        = 100
                    currentStep        = 2
                    totalSteps         = 5
                    currentDownload    = 1
                    totalDownloads     = 2
                    ErrorOccurred      = $false
                    anyUpdatePerformed = $false
                }

                $result = Invoke-DownloadLoxoneApp -WorkflowContext $workflowContext `
                    -AppTargetInfo $appTargetInfo `
                    -ScriptGlobalState ([ref]$globalState)

                $result.Succeeded | Should -Be $true
                $result.DownloadSkipped | Should -Be $true
                $result.Component | Should -Be "App"
                $result.Action | Should -Be "Download"
                Should -Invoke Invoke-LoxoneDownload -Times 0
            }
        }
    }
}

# ============================================================================
# 5. Invoke-InstallLoxoneConfig
# ============================================================================
Describe "Invoke-InstallLoxoneConfig" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-InstallLoxoneConfig -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-InstallLoxoneConfig -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'ConfigTargetInfo'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ProgressReporter'
        }

        It "WorkflowContext parameter is mandatory" {
            $cmd = Get-Command Invoke-InstallLoxoneConfig -Module LoxoneUtils
            $param = $cmd.Parameters['WorkflowContext']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "ScriptGlobalState parameter is mandatory" {
            $cmd = Get-Command Invoke-InstallLoxoneConfig -Module LoxoneUtils
            $param = $cmd.Parameters['ScriptGlobalState']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "ProgressReporter parameter is optional" {
            $cmd = Get-Command Invoke-InstallLoxoneConfig -Module LoxoneUtils
            $param = $cmd.Parameters['ProgressReporter']
            $mandatoryAttrs = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $isMandatory = $mandatoryAttrs | ForEach-Object { $_.Mandatory }
            $isMandatory | Should -Contain $false
        }
    }
}

# ============================================================================
# 6. Invoke-InstallLoxoneApp
# ============================================================================
Describe "Invoke-InstallLoxoneApp" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-InstallLoxoneApp -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-InstallLoxoneApp -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'AppTargetInfo'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ProgressReporter'
        }

        It "WorkflowContext parameter is mandatory" {
            $cmd = Get-Command Invoke-InstallLoxoneApp -Module LoxoneUtils
            $param = $cmd.Parameters['WorkflowContext']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "ScriptGlobalState parameter is mandatory" {
            $cmd = Get-Command Invoke-InstallLoxoneApp -Module LoxoneUtils
            $param = $cmd.Parameters['ScriptGlobalState']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "ProgressReporter parameter is optional" {
            $cmd = Get-Command Invoke-InstallLoxoneApp -Module LoxoneUtils
            $param = $cmd.Parameters['ProgressReporter']
            $mandatoryAttrs = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $isMandatory = $mandatoryAttrs | ForEach-Object { $_.Mandatory }
            $isMandatory | Should -Contain $false
        }
    }
}

# ============================================================================
# 7. Invoke-CheckMiniserverVersions
# ============================================================================
Describe "Invoke-CheckMiniserverVersions" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'Prerequisites'
            $cmd.Parameters.Keys | Should -Contain 'UpdateTargetsToUpdate'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
        }

        It "WorkflowContext parameter is mandatory" {
            $cmd = Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils
            $param = $cmd.Parameters['WorkflowContext']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "UpdateTargetsToUpdate parameter is mandatory" {
            $cmd = Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils
            $param = $cmd.Parameters['UpdateTargetsToUpdate']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "UpdateTargetsToUpdate parameter accepts ArrayList type" {
            $cmd = Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils
            $param = $cmd.Parameters['UpdateTargetsToUpdate']
            $param.ParameterType.FullName | Should -Be 'System.Collections.ArrayList'
        }

        It "Does not have ProgressReporter parameter" {
            $cmd = Get-Command Invoke-CheckMiniserverVersions -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Not -Contain 'ProgressReporter'
        }
    }
}

# ============================================================================
# 8. Invoke-UpdateMiniserversInBulk
# ============================================================================
Describe "Invoke-UpdateMiniserversInBulk" -Tag 'Unit', 'WorkflowSteps' {

    Context "Function availability" {
        It "Is exported from the module" {
            Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils | Should -Not -BeNullOrEmpty
        }

        It "Has expected parameters" {
            $cmd = Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils
            $cmd.Parameters.Keys | Should -Contain 'WorkflowContext'
            $cmd.Parameters.Keys | Should -Contain 'Prerequisites'
            $cmd.Parameters.Keys | Should -Contain 'UpdateTargetsToUpdate'
            $cmd.Parameters.Keys | Should -Contain 'ScriptGlobalState'
            $cmd.Parameters.Keys | Should -Contain 'ConfiguredUpdateChannel'
        }

        It "ConfiguredUpdateChannel parameter is mandatory" {
            $cmd = Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils
            $param = $cmd.Parameters['ConfiguredUpdateChannel']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }

        It "ConfiguredUpdateChannel parameter accepts string type" {
            $cmd = Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils
            $param = $cmd.Parameters['ConfiguredUpdateChannel']
            $param.ParameterType.FullName | Should -Be 'System.String'
        }

        It "UpdateTargetsToUpdate parameter accepts ArrayList type" {
            $cmd = Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils
            $param = $cmd.Parameters['UpdateTargetsToUpdate']
            $param.ParameterType.FullName | Should -Be 'System.Collections.ArrayList'
        }

        It "ScriptGlobalState parameter is mandatory" {
            $cmd = Get-Command Invoke-UpdateMiniserversInBulk -Module LoxoneUtils
            $param = $cmd.Parameters['ScriptGlobalState']
            $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -Contain $true
        }
    }
}
