# Unit tests for LoxoneUtils.MSDebugCapture (Miniserver UDP debug-stream capture + extended-logging flag).
# Facts verified live 2026-09-02 on e1 (fw 17.2.8.28): /dev/cfg/loglevel is a 0/1 boolean (5 is clamped
# to 0), /dev/sps/log/<ip> enables the stream, and a user without the debug-log right gets Code 403.
BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) { Import-Module $modulePath -ErrorAction Stop }
    }
    $Global:LogFile = Join-Path $TestDrive 'msdebug-tests.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

Describe 'ConvertTo-MSDebugLines' -Tag 'Unit' {
    It 'extracts printable runs (>= 8 chars) and drops the binary header and NUL separators' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            $header = [byte[]](1..29 | ForEach-Object { [byte]($_ % 7) })          # control bytes, no printable run
            $body = [System.Text.Encoding]::ASCII.GetBytes("TCP SendAck LATE force Ack=13039484`0PRG Check something`0")
            $lines = ConvertTo-MSDebugLines -Datagram ($header + $body)
            $lines | Should -HaveCount 2
            $lines[0] | Should -Be 'TCP SendAck LATE force Ack=13039484'
            $lines[1] | Should -Be 'PRG Check something'
        }
    }
    It 'ignores runs shorter than 8 chars and returns an empty array for pure binary' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            (ConvertTo-MSDebugLines -Datagram ([byte[]](0,1,2,3,4,5,6,7,8,9))) | Should -HaveCount 0
            (ConvertTo-MSDebugLines -Datagram ([System.Text.Encoding]::ASCII.GetBytes("abc`0defg`0"))) | Should -HaveCount 0
        }
    }
}

Describe 'Invoke-MSDebugApi response parsing' -Tag 'Unit' {
    It 'parses the LL XML Code and value and never throws on HTTP errors' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<?xml version="1.0"?> <LL control="dev/cfg/loglevel" value="1" Code="200"/>' } }
            $r = Invoke-MSDebugApi -Scheme http -HostName 10.0.0.1 -Path '/dev/cfg/loglevel' -UserName u -Password 'p'
            $r.Http | Should -Be 200; $r.Code | Should -Be 200; $r.Value | Should -Be '1'
            Mock Invoke-WebRequest { throw 'Response status code does not indicate success: 404 (Not Found).' }
            $r = Invoke-MSDebugApi -Scheme http -HostName 10.0.0.1 -Path '/dev/cfg/loglevel'
            $r.Code | Should -BeNullOrEmpty
            $r.Body | Should -Match '404'
        }
    }
    It 'sends a Basic auth header and accepts a SecureString password' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL value="0" Code="200"/>' } }
            $sec = [System.Security.SecureString]::new(); foreach ($c in 'pw'.ToCharArray()) { $sec.AppendChar($c) }
            $null = Invoke-MSDebugApi -Scheme http -HostName 10.0.0.1 -Path '/dev/cfg/loglevel' -UserName 'usr' -Password $sec
            $expected = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('usr:pw'))
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Headers.Authorization -eq $expected }
        }
    }
}

Describe 'Extended-logging flag and stream control' -Tag 'Unit' {
    It 'Get-MSExtendedLogging returns the integer value, or null on 403' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel" value="0" Code="200"/>' } }
            Get-MSExtendedLogging -Scheme http -HostName 10.0.0.1 -UserName u -Password p | Should -Be 0
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel" value="" Code="403"/>' } }
            Get-MSExtendedLogging -Scheme http -HostName 10.0.0.1 -UserName u -Password p | Should -BeNullOrEmpty
        }
    }
    It 'Set-MSExtendedLogging verifies by read-back (the firmware clamps invalid values to 0)' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            # write ACKs, read-back reports 1 -> verified
            Mock Invoke-WebRequest { param($Uri) if ($Uri -match '/loglevel/1$') { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel/1" value="" Code="200"/>' } } else { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel" value="1" Code="200"/>' } } }
            Set-MSExtendedLogging -Scheme http -HostName 10.0.0.1 -Value 1 -UserName u -Password p | Should -BeTrue
            # write ACKs, but read-back still 0 (the "5 clamped to 0" shape) -> NOT verified
            Mock Invoke-WebRequest { param($Uri) if ($Uri -match '/loglevel/1$') { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel/1" value="" Code="200"/>' } } else { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/cfg/loglevel" value="0" Code="200"/>' } } }
            Set-MSExtendedLogging -Scheme http -HostName 10.0.0.1 -Value 1 -UserName u -Password p | Should -BeFalse
        }
    }
    It 'Set-MSExtendedLogging rejects values other than 0 and 1 (boolean flag)' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            { Set-MSExtendedLogging -Scheme http -HostName 10.0.0.1 -Value 5 } | Should -Throw
        }
    }
    It 'Request-MSDebugStream reports the 403 with the LOXONE Config fix, and no reason when enabled' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/sps/log/1.2.3.4" value="" Code="403"/>' } }
            $r = Request-MSDebugStream -Scheme http -HostName 10.0.0.1 -ListenerIP 1.2.3.4 -UserName update -Password p
            $r.Enabled | Should -BeFalse
            $r.Code | Should -Be 403
            $r.Reason | Should -Match "^Code 403: user 'update' lacks the debug-log right"
            $r.Reason | Should -Match "grant 'LOXONE Config' to user 'update'"
            $r.Reason | Should -Match 'loxq grant update "LOXONE Config"'
            Should -Invoke Write-Log -Times 1 -ParameterFilter { $Level -eq 'WARN' -and $Message -match 'refused the debug stream' }
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/sps/log/1.2.3.4" value="" Code="200"/>' } }
            $r = Request-MSDebugStream -Scheme http -HostName 10.0.0.1 -ListenerIP 1.2.3.4 -UserName loxq -Password p
            $r.Enabled | Should -BeTrue
            $r.Reason | Should -BeNullOrEmpty
        }
    }
    It 'Enable-MSDebugStream returns false and logs the missing right on Code 403, true on Code 200' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/sps/log/1.2.3.4" value="" Code="403"/>' } }
            Enable-MSDebugStream -Scheme http -HostName 10.0.0.1 -ListenerIP 1.2.3.4 -UserName update -Password p | Should -BeFalse
            Should -Invoke Write-Log -Times 1 -ParameterFilter { $Message -match 'lacks the debug-log right' }
            Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '<LL control="dev/sps/log/1.2.3.4" value="" Code="200"/>' } }
            Enable-MSDebugStream -Scheme http -HostName 10.0.0.1 -ListenerIP 1.2.3.4 -UserName loxq -Password p | Should -BeTrue
            Should -Invoke Invoke-WebRequest -ParameterFilter { $Uri -eq 'http://10.0.0.1/dev/sps/log/1.2.3.4' }
        }
    }
}

Describe 'Get-MSDebugCaptureSummary (run summary line)' -Tag 'Unit' {
    # The 2026-09-22 shape: k3 captured (and re-armed after its restart), home and e1 refused with Code 403.
    BeforeAll {
        $script:Refused = "Code 403: user 'update' lacks the debug-log right - grant 'LOXONE Config' to user 'update' in Loxone Config (loxq: loxq grant update `"LOXONE Config`")"
        $script:Outcomes = @(
            [pscustomobject]@{ IP = '10.3.98.5';     Enabled = $true;  Rearmed = $true;  Reason = $null },
            [pscustomobject]@{ IP = '192.168.178.2'; Enabled = $false; Rearmed = $false; Reason = $script:Refused },
            [pscustomobject]@{ IP = '192.168.2.210'; Enabled = $false; Rearmed = $false; Reason = $script:Refused }
        )
    }
    It 'states "covered N of M Miniservers" and names every refused box with its reason' {
        $s = Get-MSDebugCaptureSummary -Outcomes $script:Outcomes
        $s.Covered | Should -Be 1
        $s.Total | Should -Be 3
        $s.AllCovered | Should -BeFalse
        $s.Headline | Should -Be 'MS debug capture covered 1 of 3 Miniservers'
        $s.Lines | Should -HaveCount 3
        $s.Lines[1] | Should -Be "  192.168.178.2: $script:Refused"
        $s.Lines[2] | Should -Be "  192.168.2.210: $script:Refused"
        $s.Text | Should -Match "grant 'LOXONE Config' to user 'update'"
        $s.Text | Should -Not -Match '10\.3\.98\.5:'     # a covered box is counted, not listed
    }
    It 'is a single clean line when every Miniserver was captured' {
        $s = Get-MSDebugCaptureSummary -Outcomes @($script:Outcomes[0])
        $s.AllCovered | Should -BeTrue
        $s.Lines | Should -HaveCount 1
        $s.Text | Should -Be 'MS debug capture covered 1 of 1 Miniservers'
    }
    It 'names a box that was not captured for a reason other than 403 (no listener, setup error)' {
        $s = Get-MSDebugCaptureSummary -Outcomes @(
            [pscustomobject]@{ IP = '10.0.0.1'; Enabled = $false; Rearmed = $false; Reason = 'capture not requested (no run-wide listener)' },
            [pscustomobject]@{ IP = '10.0.0.2'; Enabled = $false; Rearmed = $false; Reason = $null }
        )
        $s.Covered | Should -Be 0
        $s.Lines[1] | Should -Be '  10.0.0.1: capture not requested (no run-wide listener)'
        $s.Lines[2] | Should -Be '  10.0.0.2: not captured (no reason recorded)'
    }
    It 'tolerates null and empty input' {
        (Get-MSDebugCaptureSummary -Outcomes $null).Total | Should -Be 0
        (Get-MSDebugCaptureSummary -Outcomes @()).AllCovered | Should -BeTrue
    }
}

Describe 'Start-MSDebugCapture listener' -Tag 'Unit' {
    It 'receives a datagram on the bound port, tags it with the sender IP, and stops cleanly' {
        InModuleScope LoxoneUtils.MSDebugCapture {
            Mock Write-Log {}
            $out = Join-Path $TestDrive 'msdebug_unit.log'
            $port = 27777   # not the production port: the suite may run while a real capture is up
            $h = Start-MSDebugCapture -OutputPath $out -Port $port
            $h | Should -Not -BeNullOrEmpty
            try {
                $tx = New-Object System.Net.Sockets.UdpClient
                $payload = [byte[]](1..29 | ForEach-Object { [byte]0 }) + [System.Text.Encoding]::ASCII.GetBytes("UNITTEST datagram line`0")
                $null = $tx.Send($payload, $payload.Length, '127.0.0.1', $port); $tx.Close()
                Start-Sleep -Seconds 3
            } finally { Stop-MSDebugCapture -Handle $h }
            $content = Get-Content $out -Raw
            $content | Should -Match '\[127\.0\.0\.1\] UNITTEST datagram line'
            $content | Should -Match 'capture stopped .* 1 datagrams, 1 lines'
        }
    }
    It 'Stop-MSDebugCapture tolerates a null handle' {
        InModuleScope LoxoneUtils.MSDebugCapture { { Stop-MSDebugCapture -Handle $null } | Should -Not -Throw }
    }
}

Describe 'Debug-capture teardown lives in the function that ARMS the stream' -Tag 'Unit' {
    # Measured 2026-09-04: K3 (production) streamed ~77 datagrams/s to this workstation for 58 h
    # after its 2026-09-02 update, and /dev/cfg/loglevel was still 1 two days later. The teardown
    # (restore the flag, Disable-MSDebugStream) sat in Test-LoxoneMiniserverUpdateLevel's finally,
    # gated on flags only Invoke-MSUpdate ever sets and using $schemeInInvoke / $hostForPingInInvoke,
    # which only exist in Invoke-MSUpdate. It could never run. These tests read the SOURCE, because
    # the defect was one of placement - the right code at the wrong `} finally {` - and a mock-driven
    # test of either function in isolation would have passed before and after.
    BeforeAll {
        $script:msSrc = Get-Content -Raw (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'LoxoneUtils\LoxoneUtils.Miniserver.psm1')
        $script:fnStarts = [regex]::Matches($script:msSrc, '(?m)^function (\S+)') | ForEach-Object { [pscustomobject]@{ Name = $_.Groups[1].Value; Pos = $_.Index } }
        $script:OwnerOf = { param($pos) ($script:fnStarts | Where-Object Pos -le $pos | Select-Object -Last 1).Name }
    }
    It 'Disable-MSDebugStream teardown is inside Invoke-MSUpdate, and nowhere else' {
        $hits = [regex]::Matches($script:msSrc, 'Disable-MSDebugStream @dbgArgs')
        $hits.Count | Should -Be 1
        (& $script:OwnerOf $hits[0].Index) | Should -Be 'Invoke-MSUpdate'
    }
    It 'the persisted extended-logging flag is restored in Invoke-MSUpdate too' {
        $hits = [regex]::Matches($script:msSrc, 'Set-MSExtendedLogging @dbgArgs -Value \$debugFlagOld')
        $hits.Count | Should -Be 1
        (& $script:OwnerOf $hits[0].Index) | Should -Be 'Invoke-MSUpdate'
    }
    It 'the teardown sits AFTER the polling-loop re-arm, in the same function' {
        # The re-arm (Enable-MSDebugStream after the MS answers again) is the copy that leaked: it
        # runs after the restart the old comment relied on to kill the stream. The disable must
        # come later in the same function or the re-armed stream outlives the run.
        $rearm = $script:msSrc.IndexOf('$debugStreamRearmed = $true')
        $teardown = $script:msSrc.IndexOf('Disable-MSDebugStream @dbgArgs')
        $rearm | Should -BeGreaterThan 0
        $teardown | Should -BeGreaterThan $rearm
        (& $script:OwnerOf $rearm) | Should -Be 'Invoke-MSUpdate'
    }
    It 'Test-LoxoneMiniserverUpdateLevel no longer carries a teardown it cannot execute' {
        $start = ($script:fnStarts | Where-Object Name -eq 'Test-LoxoneMiniserverUpdateLevel').Pos
        $next = ($script:fnStarts | Where-Object Pos -gt $start | Select-Object -First 1).Pos
        $body = $script:msSrc.Substring($start, $next - $start)
        # CODE only - a comment explaining where the block went is allowed to name it
        $code = ($body -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'Disable-MSDebugStream'
        $code | Should -Not -Match 'schemeInInvoke'
    }
    It 'a failed disable or restore is LOUD and names the manual fix' {
        # A silent best-effort teardown is how K3 sat streaming for 58 hours.
        $script:msSrc | Should -Match 'debug stream NOT confirmed off'
        $script:msSrc | Should -Match 'extended-logging flag NOT restored'
        $script:msSrc | Should -Match 'GET /dev/sps/log'
        $script:msSrc | Should -Match 'GET /dev/cfg/loglevel/\$debugFlagOld'
    }
}
