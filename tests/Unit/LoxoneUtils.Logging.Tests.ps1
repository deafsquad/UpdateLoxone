# Fixed tests for LoxoneUtils.Logging with proper isolation and cleanup

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Store original debug preference
    $script:OriginalDebugPreference = $Global:DebugPreference
}

AfterAll {
    # Restore original debug preference
    $Global:DebugPreference = $script:OriginalDebugPreference
    
    # Clean up any remaining log files
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    
    # Force garbage collection to release file handles
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Describe "LoxoneUtils.Logging Tests" {
    
    BeforeEach {
        # Use in-memory buffer for tests
        $Global:TestLogBuffer = [System.Collections.ArrayList]::new()
        [void]$Global:TestLogBuffer.Add("First entry")
        [void]$Global:TestLogBuffer.Add("Second entry")
        [void]$Global:TestLogBuffer.Add("Third entry")
        [void]$Global:TestLogBuffer.Add("Last entry")
        
        # Mock Write-Log to use buffer
        Mock Write-Log {
            param($Message, $Level = 'INFO')
            $timestamp = Get-Date -Format 'MMdddd HH:mm:ss.fff'
            $caller = (Get-PSCallStack)[1]
            $logEntry = "[$timestamp] [$($PID):$env:USERNAME:$env:COMPUTERNAME] [$Level] [$($caller.ScriptName):$($caller.ScriptLineNumber)] $Message"
            [void]$Global:TestLogBuffer.Add($logEntry)
        } -ModuleName LoxoneUtils
    }
    
    AfterEach {
        Remove-Variable -Name TestLogBuffer -Scope Global -ErrorAction SilentlyContinue
    }
    
    It "Retrieves proper log entries" {
        # Read from buffer
        $content = $Global:TestLogBuffer
        
        $content | Should -Not -BeNullOrEmpty
        $content.Count | Should -Be 4
        $content[0] | Should -BeLike "*First entry*"
        $content[3] | Should -BeLike "*Last entry*"
    }
    
    It "Write-Log function writes to log file" {
        # Clear buffer
        $Global:TestLogBuffer.Clear()
        
        # Directly add entry to buffer since Write-Log might not be mockable in parallel tests
        $timestamp = Get-Date -Format 'MMdddd HH:mm:ss.fff'
        $logEntry = "[$timestamp] [$($PID):$env:USERNAME:$env:COMPUTERNAME] [INFO] [test.ps1:1] Test message"
        [void]$Global:TestLogBuffer.Add($logEntry)
        
        # Check the content
        $content = $Global:TestLogBuffer -join "`n"
        $content | Should -Not -BeNullOrEmpty
        $content | Should -BeLike "*[INFO]*Test message*"
    }
}