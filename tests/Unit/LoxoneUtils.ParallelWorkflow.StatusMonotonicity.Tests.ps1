# Regression tests for the Miniserver status monotonicity guard.
# Bug (2026-07-17, MS 192.168.178.2): the worker re-enqueues its FULL status history at job end,
# and the watcher removed the IP from all buckets and re-added it to whatever state each message
# carried - so a replayed 'Downloading' processed after 'Completed' dragged the MS back to
# Downloading and the display walked backwards. Test-ShouldApplyMSStatus is the extracted guard.
BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) { Import-Module $modulePath -ErrorAction Stop }
    }
}

Describe 'Test-ShouldApplyMSStatus (status monotonicity guard)' -Tag 'Unit' {
    It 'rejects a non-terminal update for an IP already in a terminal state' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $tracker = @{ LastTsByIP = @{}; TerminalIPs = @{ '10.0.0.1' = $true } }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.1' -State 'Downloading' -Timestamp (Get-Date)) | Should -BeFalse
        }
    }

    It 'allows a terminal update even when the IP is already terminal (Completed stays Completed)' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $tracker = @{ LastTsByIP = @{}; TerminalIPs = @{ '10.0.0.1' = $true } }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.1' -State 'Completed' -Timestamp (Get-Date)) | Should -BeTrue
        }
    }

    It 'allows the first update for a fresh IP' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $tracker = @{ LastTsByIP = @{}; TerminalIPs = @{} }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.2' -State 'Downloading' -Timestamp (Get-Date)) | Should -BeTrue
        }
    }

    It 'rejects an update strictly older than the newest already applied for that IP' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $t2 = Get-Date
            $t1 = $t2.AddSeconds(-30)
            $tracker = @{ LastTsByIP = @{ '10.0.0.3' = $t2 }; TerminalIPs = @{} }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.3' -State 'Downloading' -Timestamp $t1) | Should -BeFalse
        }
    }

    It 'allows an update newer than the last applied for that IP' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $t2 = Get-Date
            $t3 = $t2.AddSeconds(30)
            $tracker = @{ LastTsByIP = @{ '10.0.0.3' = $t2 }; TerminalIPs = @{} }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.3' -State 'Verifying' -Timestamp $t3) | Should -BeTrue
        }
    }

    It 'reproduces the replay bug: a replayed Downloading after Completed is rejected' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            # Real sequence: live updates applied (ending Completed), then the worker replays its
            # history - a Downloading carrying its ORIGINAL (older) timestamp must not regress the MS.
            $tDownload = Get-Date
            $tCompleted = $tDownload.AddSeconds(120)
            $tracker = @{ LastTsByIP = @{ '192.168.178.2' = $tCompleted }; TerminalIPs = @{ '192.168.178.2' = $true } }

            # Replayed stale Downloading (older timestamp, non-terminal) -> rejected by BOTH rules
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '192.168.178.2' -State 'Downloading' -Timestamp $tDownload) | Should -BeFalse
            # Replayed stale Updating -> also rejected
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '192.168.178.2' -State 'Updating' -Timestamp $tDownload.AddSeconds(60)) | Should -BeFalse
        }
    }

    It 'rejects a timeless (no Timestamp) non-terminal update for a terminal IP via rule 1' {
        InModuleScope LoxoneUtils.ParallelWorkflow {
            $tracker = @{ LastTsByIP = @{}; TerminalIPs = @{ '10.0.0.4' = $true } }
            (Test-ShouldApplyMSStatus -Tracker $tracker -IP '10.0.0.4' -State 'Downloading' -Timestamp $null) | Should -BeFalse
        }
    }
}
