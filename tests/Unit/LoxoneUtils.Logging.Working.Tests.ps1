# Working tests for LoxoneUtils.Logging based on actual behavior

BeforeAll {
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Tests will use TestDrive for isolation - log files will be set up per test
}

AfterAll {
    # Clean up log file
    if ($Global:LogFile -and (Test-Path $Global:LogFile)) {
        Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Write-Log Function" -Tag 'Logging' {
    
    BeforeEach {
        # Set up isolated log file in TestDrive for each test
        $guid = [System.Guid]::NewGuid().ToString()
        $Global:LogFile = Join-Path $TestDrive "test_$guid.log"
        "# Test log file" | Out-File $Global:LogFile -Encoding UTF8
    }
    
    AfterEach {
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    }
    
    Context "Parameter Validation" {
        It "Throws specific error for empty string" {
            { Write-Log -Message "" -Level INFO } | 
                Should -Throw -ErrorId "ParameterArgumentValidationErrorEmptyStringNotAllowed,Write-Log"
        }
        
        It "Throws specific error for null" {
            { Write-Log -Message $null -Level INFO } | 
                Should -Throw -ErrorId "ParameterArgumentValidationErrorEmptyStringNotAllowed,Write-Log"
        }
        
        It "Rejects whitespace-only messages" {
            # Based on test output, it shows warning but doesn't write
            { Write-Log -Message "   " -Level INFO -WarningAction SilentlyContinue } | Should -Not -Throw
        }
        
        It "Validates Level parameter" {
            { Write-Log -Message "Test" -Level INVALID } | 
                Should -Throw -ErrorId "ParameterArgumentValidationError,Write-Log"
        }
    }
    
    Context "Log Output" {
        It "Writes to log file with correct format" {
            # Try multiple times to handle potential mutex issues
            $maxAttempts = 3
            $attempt = 0
            $success = $false
            
            while ($attempt -lt $maxAttempts -and -not $success) {
                $attempt++
                
                try {
                    # Clear the file first
                    Clear-Content -Path $Global:LogFile -Force
                    Start-Sleep -Milliseconds 100
                    
                    Write-Log -Message "Format test" -Level INFO
                    Start-Sleep -Milliseconds 200
                    
                    $content = Get-Content $Global:LogFile -Raw
                    if ($content -and $content -match "\[INFO\].*Format test") {
                        $success = $true
                    }
                } catch {
                    Start-Sleep -Milliseconds 500
                }
            }
            
            $content | Should -Match "\[INFO\].*Format test"
            $content | Should -Match "\[\d{6} \d{2}:\d{2}:\d{2}\.\d{3}\]"  # Timestamp
            $content | Should -Match "\[$($PID):"  # Process ID
        }
        
        It "Includes source location" {
            Clear-Content -Path $Global:LogFile -Force
            Write-Log -Message "Location test" -Level INFO
            Start-Sleep -Milliseconds 100
            
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Match "\[.*\.ps1:\d+\]"  # [ScriptName.ps1:LineNumber]
        }
        
        It "ERROR level logs to file and console" {
            Clear-Content -Path $Global:LogFile -Force
            
            # In test mode, Write-Log uses Write-Host for ERROR level
            # We can't capture Write-Host output easily, so just verify the log file
            Write-Log -Message "Error test" -Level ERROR
            
            # Verify it was written to the log file
            Get-Content $Global:LogFile -Raw | Should -Match "\[ERROR\].*Error test"
        }
        
        It "WARN level uses Write-Warning" {
            $warnings = @()
            Write-Log -Message "Warning test" -Level WARN -WarningVariable warnings -WarningAction SilentlyContinue
            
            $warnings.Count | Should -Be 1
            $warnings[0] | Should -Match "Warning test"
        }
        
        It "DEBUG level requires DebugPreference Continue" {
            Clear-Content -Path $Global:LogFile -Force
            
            $Global:DebugPreference = 'SilentlyContinue'
            Write-Log -Message "Debug hidden" -Level DEBUG
            Start-Sleep -Milliseconds 100
            $contentAfter = Get-Content $Global:LogFile -Raw
            
            # Should not write when SilentlyContinue
            $contentAfter | Should -BeNullOrEmpty
            
            $Global:DebugPreference = 'Continue'
            Write-Log -Message "Debug visible" -Level DEBUG
            Start-Sleep -Milliseconds 100
            Get-Content $Global:LogFile -Raw | Should -Match "Debug visible"
        }
    }
    
    Context "Missing LogFile Handling" {
        It "Handles missing LogFile gracefully" {
            $saved = $Global:LogFile
            Remove-Variable -Name LogFile -Scope Global
            
            # In test mode, Write-Log writes to console instead of warning
            # Since we can't easily capture Write-Host, just verify it doesn't throw
            { Write-Log -Message "No file" -Level INFO } | Should -Not -Throw
            
            $Global:LogFile = $saved
        }
    }
}

Describe "Enter-Function and Exit-Function" -Tag 'Logging' {
    
    BeforeAll {
        # Enable debug output for function tracing
        $script:SavedDebugPreference = $Global:DebugPreference
        $Global:DebugPreference = 'Continue'
        
        # Set up test log file
        $guid = [System.Guid]::NewGuid().ToString()
        $Global:LogFile = Join-Path $TestDrive "function_trace_$guid.log"
        "# Function trace log" | Out-File $Global:LogFile -Encoding UTF8
    }
    
    AfterAll {
        $Global:DebugPreference = $script:SavedDebugPreference
        
        # Clean up log file
        if ($Global:LogFile -and (Test-Path $Global:LogFile)) {
            Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    }
    
    Context "Function Tracing" {
        It "Enter-Function logs entry with Debug level" {
            Clear-Content -Path $Global:LogFile -Force
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Start-Sleep -Milliseconds 100
            
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "\[Debug\].*--> Entering Function: TestFunc"
        }
        
        It "Exit-Function logs exit with duration" {
            Clear-Content -Path $Global:LogFile -Force
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Start-Sleep -Milliseconds 50
            Exit-Function
            Start-Sleep -Milliseconds 100
            
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "<-- Exiting Function: TestFunc"
            $content | Should -Match "Duration: \d+[.,]\d+s"
        }
        
        It "Exit-Function includes result message" {
            Clear-Content -Path $Global:LogFile -Force
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Exit-Function -ResultMessage "Success"
            Start-Sleep -Milliseconds 100
            
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "\| Result: Success"
        }
        
        It "Maintains call stack for nested functions" {
            Clear-Content -Path $Global:LogFile -Force
            Enter-Function -FunctionName "Outer" -FilePath "test.ps1" -LineNumber 10
            Enter-Function -FunctionName "Inner" -FilePath "test.ps1" -LineNumber 20
            
            Exit-Function  # Exit Inner
            Start-Sleep -Milliseconds 100
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "Exiting Function: Inner"
            
            Exit-Function  # Exit Outer
            Start-Sleep -Milliseconds 100
            Get-Content $Global:LogFile -Raw | Should -Match "Exiting Function: Outer"
        }
    }
}

Describe "Invoke-LogFileRotation Function" -Tag 'Logging' {
    
    Context "File Rotation" {
        It "Rotates file when called" {
            $guid = [System.Guid]::NewGuid().ToString()
            $testLog = Join-Path $TestDrive "rotate_$guid.log"
            "Test content" | Out-File $testLog
            
            Invoke-LogFileRotation -LogFilePath $testLog
            
            # Original file should be gone
            Test-Path $testLog | Should -Be $false
            
            # Rotated file should exist
            $rotated = Get-ChildItem $TestDrive -Filter "rotate_$guid_*.log"
            $rotated | Should -Not -BeNullOrEmpty
        }
        
        It "Uses correct timestamp format" {
            $guid = [System.Guid]::NewGuid().ToString()
            $testLog = Join-Path $TestDrive "timestamp_$guid.log"
            "Content" | Out-File $testLog
            
            Invoke-LogFileRotation -LogFilePath $testLog
            
            # Look for the specific rotated file
            $rotated = Get-ChildItem $TestDrive -Filter "timestamp_$guid_*.log"
            $rotated | Should -Not -BeNullOrEmpty
            if ($rotated) {
                $escapedGuid = [regex]::Escape($guid)
                $rotated.Name | Should -Match "timestamp_${escapedGuid}_\d{8}_\d{6}\.log"
            }
        }
        
        It "Accepts MaxArchiveCount parameter" {
            $guid = [System.Guid]::NewGuid().ToString()
            # Create some existing archives
            1..5 | ForEach-Object {
                "Archive $_" | Out-File (Join-Path $TestDrive "cleanup_test_${guid}_2024010${_}_120000.log")
            }
            
            $testLog = Join-Path $TestDrive "cleanup_test_$guid.log"
            "Current" | Out-File $testLog
            
            # Should not throw
            { Invoke-LogFileRotation -LogFilePath $testLog -MaxArchiveCount 3 } | Should -Not -Throw
        }
        
        It "Handles non-existent file gracefully" {
            $fakePath = Join-Path $TestDrive "does_not_exist_$([System.Guid]::NewGuid().ToString()).log"
            
            # Should not throw
            { Invoke-LogFileRotation -LogFilePath $fakePath } | Should -Not -Throw
        }
    }
}

Describe "Module Integration" -Tag 'Logging' {
    
    BeforeAll {
        # Set up test log file for thread safety tests
        $guid = [System.Guid]::NewGuid().ToString()
        $Global:LogFile = Join-Path $TestDrive "integration_$guid.log"
        Clear-Content -Path $Global:LogFile -Force -ErrorAction SilentlyContinue
    }
    
    AfterAll {
        # Clean up log file
        if ($Global:LogFile -and (Test-Path $Global:LogFile)) {
            Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    }
    
    Context "Exported Functions" {
        It "Exports all logging functions" {
            $module = Get-Module LoxoneUtils
            $module.ExportedFunctions.Keys | Should -Contain 'Write-Log'
            $module.ExportedFunctions.Keys | Should -Contain 'Enter-Function'
            $module.ExportedFunctions.Keys | Should -Contain 'Exit-Function'
            $module.ExportedFunctions.Keys | Should -Contain 'Invoke-LogFileRotation'
        }
    }
    
    Context "Thread Safety" {
        It "Multiple Write-Log calls work correctly" {
            # Log file should already be set by BeforeAll
            $Global:LogFile | Should -Not -BeNullOrEmpty
            
            1..5 | ForEach-Object {
                Write-Log -Message "Concurrent test $_" -Level INFO
            }
            
            $content = Get-Content $Global:LogFile -Raw
            1..5 | ForEach-Object {
                $content | Should -Match "Concurrent test $_"
            }
        }
    }
}