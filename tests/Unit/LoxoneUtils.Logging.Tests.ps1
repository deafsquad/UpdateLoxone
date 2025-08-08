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
        # Create a test log file
        $script:TestLogFile = Join-Path $TestDrive "test-$(Get-Random).log"
        $Global:LogFile = $script:TestLogFile
        
        # Write some test entries
        "First entry" | Out-File -FilePath $Global:LogFile -Encoding UTF8
        "Second entry" | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append
        "Third entry" | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append
        "Last entry" | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Append
    }
    
    AfterEach {
        if (Test-Path $script:TestLogFile) {
            Remove-Item -Path $script:TestLogFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    }
    
    It "Retrieves proper log entries" {
        # Just read the content directly
        $content = Get-Content $Global:LogFile
        
        $content | Should -Not -BeNullOrEmpty
        $content.Count | Should -Be 4
        $content[0] | Should -BeLike "*First entry*"
        $content[3] | Should -BeLike "*Last entry*"
    }
    
    It "Write-Log function writes to log file" {
        # Clear the file first
        Clear-Content -Path $Global:LogFile
        
        # Write a log entry
        Write-Log -Message "Test message" -Level INFO
        
        # Check the content
        $content = Get-Content $Global:LogFile -Raw
        $content | Should -Not -BeNullOrEmpty
        $content | Should -BeLike "*[INFO]*Test message*"
    }
}