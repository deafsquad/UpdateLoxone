# Regression tests for Invoke-MiniserverWebRequest parameter handling.
# Bug (2026-06-11): the PS7 HTTPS branch removed 'SkipCertificateCheck' from the CALLER's
# hashtable (by-reference mutation), so polling loops reusing $verifyParams lost the cert
# bypass after the first attempt and failed with RemoteCertificateNameMismatch.
BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) { Import-Module $modulePath -ErrorAction Stop }
    }
    $Global:SuppressLoxoneToastInit = $true
    $script:TestTempPath = Join-Path $TestDrive 'MiniserverWebRequest'
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

Describe 'Invoke-MiniserverWebRequest parameter immutability' -Tag 'Unit' {
    It 'does not remove SkipCertificateCheck from the caller hashtable (PS7 HTTPS path)' -Skip:($PSVersionTable.PSVersion.Major -lt 6) {
        InModuleScope LoxoneUtils.Miniserver {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Content = '<LL value="1.0.0.0"/>' } }

            $callerParams = @{
                Uri                  = 'https://192.0.2.1/dev/cfg/version'
                UseBasicParsing      = $true
                TimeoutSec           = 3
                ErrorAction          = 'Stop'
                SkipCertificateCheck = $true
            }

            $null = Invoke-MiniserverWebRequest -Parameters $callerParams

            # The polling loop reuses this hashtable for up to 150 attempts - the bypass flag
            # must survive the call, otherwise only the first poll is protected.
            $callerParams.ContainsKey('SkipCertificateCheck') | Should -BeTrue -Because 'the caller hashtable must not be mutated'
        }
    }

    It 'still passes SkipCertificateCheck through to Invoke-WebRequest on repeated calls' -Skip:($PSVersionTable.PSVersion.Major -lt 6) {
        InModuleScope LoxoneUtils.Miniserver {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Content = 'ok' } }

            $callerParams = @{
                Uri                  = 'https://192.0.2.1/dev/cfg/version'
                SkipCertificateCheck = $true
            }

            $null = Invoke-MiniserverWebRequest -Parameters $callerParams
            $null = Invoke-MiniserverWebRequest -Parameters $callerParams   # second call = the poll-loop reuse case

            # Both calls must reach Invoke-WebRequest with the bypass active
            Should -Invoke Invoke-WebRequest -Times 2 -Exactly -ParameterFilter { $SkipCertificateCheck -eq $true }
        }
    }
}
