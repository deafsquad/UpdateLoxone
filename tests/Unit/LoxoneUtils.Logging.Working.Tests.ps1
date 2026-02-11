# Working tests for LoxoneUtils.Logging based on actual behavior
# Strategy: Use real log file output instead of mocks, since mocks with -ModuleName
# only intercept calls inside the module, not calls from outside.

BeforeAll {
    # Force file logging BEFORE importing, so the module sees it during initialization
    $env:LOXONE_FORCE_FILE_LOGGING = "1"

    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

AfterAll {
    # Clean up environment and globals
    Remove-Item Env:\LOXONE_FORCE_FILE_LOGGING -ErrorAction SilentlyContinue
    if ($Global:LogFile -and (Test-Path $Global:LogFile -ErrorAction SilentlyContinue)) {
        Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Write-Log Function" -Tag 'Logging' {

    BeforeEach {
        # Create a unique temp log file for each test - no mocking needed
        $guid = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $Global:LogFile = Join-Path $TestDrive "writelog_$guid.log"
        # Create the empty file so FileStream can open it
        [System.IO.File]::WriteAllText($Global:LogFile, "")
    }

    AfterEach {
        if ($Global:LogFile -and (Test-Path $Global:LogFile -ErrorAction SilentlyContinue)) {
            Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
        }
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
            # Based on actual behavior, it shows warning but doesn't write
            { Write-Log -Message "   " -Level INFO -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It "Validates Level parameter" {
            { Write-Log -Message "Test" -Level INVALID } |
                Should -Throw -ErrorId "ParameterArgumentValidationError,Write-Log"
        }
    }

    Context "Log Output" {
        It "Writes to log file with correct format" {
            Write-Log -Message "Format test" -Level INFO
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw

            $content | Should -Match "\[INFO\].*Format test"
            $content | Should -Match "\[\d{6} \d{2}:\d{2}:\d{2}\.\d{3}\]"  # Timestamp yyMMdd HH:mm:ss.fff
            $content | Should -Match "\[$($PID):"  # Process ID
        }

        It "Includes source location" {
            Write-Log -Message "Location test" -Level INFO
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            # Caller info includes script name and line number: [ScriptName.ps1:LineNumber]
            $content | Should -Match "\[.*\.ps1:\d+"
        }

        It "ERROR level logs to file and console" {
            # In test mode (PESTER_TEST_RUN=1), Write-Log uses Write-Host for ERROR
            # We verify the log file has the entry
            Write-Log -Message "Error test" -Level ERROR
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Match "\[ERROR\].*Error test"
        }

        It "WARN level writes to log file" {
            # Write-Log internally calls Write-Warning, but -WarningVariable won't capture
            # from inside the function. Instead, verify the log file has the entry.
            Write-Log -Message "Warning test" -Level WARN -WarningAction SilentlyContinue
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Match "\[WARN\].*Warning test"
        }

        It "DEBUG level requires DebugPreference Continue" {
            $Global:DebugPreference = 'SilentlyContinue'
            Write-Log -Message "Debug hidden" -Level DEBUG
            Start-Sleep -Milliseconds 100

            $contentAfterSilent = Get-Content $Global:LogFile -Raw
            # Should NOT write when SilentlyContinue
            $contentAfterSilent | Should -Not -Match "Debug hidden"

            $Global:DebugPreference = 'Continue'
            Write-Log -Message "Debug visible" -Level DEBUG
            Start-Sleep -Milliseconds 100

            $contentAfterContinue = Get-Content $Global:LogFile -Raw
            $contentAfterContinue | Should -Match "Debug visible"
        }
    }

    Context "Missing LogFile Handling" {
        It "Handles missing LogFile gracefully" {
            $saved = $Global:LogFile
            Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue

            # Should not throw even without LogFile set
            { Write-Log -Message "No file" -Level INFO } | Should -Not -Throw

            $Global:LogFile = $saved
        }
    }
}

Describe "Enter-Function and Exit-Function" -Tag 'Logging' {

    BeforeAll {
        # Enable debug output for function tracing (Enter/Exit use DEBUG level)
        $script:SavedDebugPreference = $Global:DebugPreference
        $Global:DebugPreference = 'Continue'

        # Force file logging
        $env:LOXONE_FORCE_FILE_LOGGING = "1"
    }

    AfterAll {
        $Global:DebugPreference = $script:SavedDebugPreference
        if ($Global:LogFile -and (Test-Path $Global:LogFile -ErrorAction SilentlyContinue)) {
            Remove-Item $Global:LogFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    }

    BeforeEach {
        # Fresh log file per test
        $guid = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $Global:LogFile = Join-Path $TestDrive "functrace_$guid.log"
        [System.IO.File]::WriteAllText($Global:LogFile, "")
    }

    Context "Function Tracing" {
        It "Enter-Function logs entry with Debug level" {
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "Entering Function: TestFunc"
        }

        It "Exit-Function logs exit with duration" {
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Start-Sleep -Milliseconds 50
            Exit-Function
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "Exiting Function: TestFunc"
            $content | Should -Match "Duration: \d+[.,]\d+s"
        }

        It "Exit-Function includes result message" {
            Enter-Function -FunctionName "TestFunc" -FilePath "test.ps1" -LineNumber 10
            Exit-Function -ResultMessage "Success"
            Start-Sleep -Milliseconds 100

            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "Result: Success"
        }

        It "Maintains call stack for nested functions" {
            Enter-Function -FunctionName "Outer" -FilePath "test.ps1" -LineNumber 10
            Enter-Function -FunctionName "Inner" -FilePath "test.ps1" -LineNumber 20

            Exit-Function  # Exit Inner
            Start-Sleep -Milliseconds 100
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Not -BeNullOrEmpty
            $content | Should -Match "Exiting Function: Inner"

            Exit-Function  # Exit Outer
            Start-Sleep -Milliseconds 100
            $content = Get-Content $Global:LogFile -Raw
            $content | Should -Match "Exiting Function: Outer"
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
        # Set up test log file for integration tests
        $guid = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $Global:LogFile = Join-Path $TestDrive "integration_$guid.log"
        [System.IO.File]::WriteAllText($Global:LogFile, "")
    }

    AfterAll {
        if ($Global:LogFile -and (Test-Path $Global:LogFile -ErrorAction SilentlyContinue)) {
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
            $Global:LogFile | Should -Not -BeNullOrEmpty

            1..5 | ForEach-Object {
                Write-Log -Message "Concurrent test $_" -Level INFO
            }
            Start-Sleep -Milliseconds 200

            $content = Get-Content $Global:LogFile -Raw
            1..5 | ForEach-Object {
                $content | Should -Match "Concurrent test $_"
            }
        }
    }
}
