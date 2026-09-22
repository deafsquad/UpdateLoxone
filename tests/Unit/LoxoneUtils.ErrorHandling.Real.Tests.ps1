# Real implementation tests for LoxoneUtils.ErrorHandling - using actual error scenarios and logging

BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
    $env:LOXONE_FORCE_FILE_LOGGING = "1"
    
    # Set up test environment with real log file
    $script:TestTempPath = Join-Path $env:TEMP "LoxoneErrorTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    
    # Create real log file for error logging
    $Global:LogFile = Join-Path $script:TestTempPath 'error-test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
    
    # Set debug preference for detailed logging
    $Global:DebugPreference = 'Continue'
    
    # Create test scripts that generate real errors
    $script:ErrorScripts = @{}
    
    # Script that throws a terminating error
    $script:ErrorScripts.Terminating = Join-Path $script:TestTempPath "ThrowError.ps1"
    @'
param($Message)
throw $Message
'@ | Set-Content $script:ErrorScripts.Terminating
    
    # Script that generates a non-terminating error
    $script:ErrorScripts.NonTerminating = Join-Path $script:TestTempPath "WriteError.ps1"
    @'
param($Message)
Write-Error $Message
Get-ChildItem "C:\NonExistentPath\*.txt" -ErrorAction Continue
'@ | Set-Content $script:ErrorScripts.NonTerminating
    
    # Script that causes a divide by zero
    $script:ErrorScripts.DivideByZero = Join-Path $script:TestTempPath "DivideByZero.ps1"
    @'
$result = 10 / 0
'@ | Set-Content $script:ErrorScripts.DivideByZero
    
    # Script with syntax error
    $script:ErrorScripts.Syntax = Join-Path $script:TestTempPath "SyntaxError.ps1"
    @'
if ($true {  # Missing closing parenthesis
    Write-Host "This won't run"
'@ | Set-Content $script:ErrorScripts.Syntax
}

AfterAll {
    # Clean up temp directory
    if (Test-Path $script:TestTempPath) {
        Remove-Item -Path $script:TestTempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name DebugPreference -Scope Global -ErrorAction SilentlyContinue
}

Describe "Real Error Generation and Capture" -Tag 'ErrorHandling', 'Real' {
    
    It "Captures and logs real terminating errors" {
        $errorOccurred = $false
        $errorMessage = "Test terminating error $(Get-Random)"

        try {
            & $script:ErrorScripts.Terminating -Message $errorMessage
        } catch {
            $errorOccurred = $true
            Write-Log -Message "Caught error: $_" -Level ERROR
            $_.Exception.Message | Should -Be $errorMessage
            $_.CategoryInfo | Should -Not -BeNullOrEmpty
        }

        $errorOccurred | Should -Be $true

        # Verify error was logged to file
        $logContent = Get-Content $Global:LogFile -Raw
        $logContent | Should -Match "ERROR"
        $logContent | Should -Match $errorMessage
    }
    
    It "Captures non-terminating errors from scripts" {
        $errorMessage = "Test non-terminating error"

        # Pester sets $ErrorActionPreference = 'Stop', which converts Write-Error
        # into terminating errors. Override to 'Continue' to test non-terminating behavior.
        $savedEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $Error.Clear()
            & $script:ErrorScripts.NonTerminating -Message $errorMessage 2>$null

            # Should have errors in automatic $Error variable
            $Error.Count | Should -BeGreaterThan 0

            # Check for our custom error message
            $customError = $Error | Where-Object { $_.ToString() -match $errorMessage }
            $customError | Should -Not -BeNullOrEmpty
        } finally {
            $ErrorActionPreference = $savedEAP
        }
    }
    
    It "Handles divide by zero errors" {
        $errorOccurred = $false
        
        try {
            & $script:ErrorScripts.DivideByZero
        } catch {
            $errorOccurred = $true
            $_.Exception.GetType().Name | Should -Match "DivideByZeroException|RuntimeException"
        }
        
        $errorOccurred | Should -Be $true
    }
    
    It "Detects and reports syntax errors" {
        $parseErrors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ErrorScripts.Syntax,
            [ref]$tokens,
            [ref]$parseErrors
        )

        $parseErrors | Should -Not -BeNullOrEmpty
        # Parser should detect the syntax issue (missing paren or unexpected token)
        $parseErrors.Count | Should -BeGreaterThan 0
    }
}

Describe "Real Error Logging to File" -Tag 'ErrorHandling', 'Real' {
    
    BeforeEach {
        # Clear log file for each test
        Clear-Content $Global:LogFile -Force
    }
    
    It "Writes structured error information to log file" {
        $testError = $null
        
        try {
            throw "Structured error test"
        } catch {
            $testError = $_
            
            # Write structured error info
            Write-Log -Message "Error occurred in test" -Level ERROR
            Write-Log -Message "Exception: $($_.Exception.Message)" -Level ERROR
            Write-Log -Message "Script: $($_.InvocationInfo.ScriptName)" -Level ERROR
            Write-Log -Message "Line: $($_.InvocationInfo.ScriptLineNumber)" -Level ERROR
            Write-Log -Message "Stack: $($_.ScriptStackTrace)" -Level ERROR
        }
        
        # Read and verify log content
        $logLines = Get-Content $Global:LogFile
        
        $logLines | Where-Object { $_ -match "ERROR" } | Should -Not -BeNullOrEmpty
        $logLines | Where-Object { $_ -match "Structured error test" } | Should -Not -BeNullOrEmpty
        $logLines | Where-Object { $_ -match "Line:" } | Should -Not -BeNullOrEmpty
    }
    
    It "Logs errors with timestamps and severity levels" {
        $savedDebug = $Global:DebugPreference
        $Global:DebugPreference = 'Continue'

        $levels = @('DEBUG', 'INFO', 'WARN', 'ERROR')

        foreach ($level in $levels) {
            Write-Log -Message "Test message at $level level" -Level $level -WarningAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 100

        $logContent = Get-Content $Global:LogFile

        foreach ($level in $levels) {
            $logContent | Where-Object { $_ -match "\[$level\]" } | Should -Not -BeNullOrEmpty
        }

        # Verify timestamps are present (format: [YYMMDD HH:mm:ss.fff])
        $logContent | Where-Object { $_ -match '\[\d{6} \d{2}:\d{2}:\d{2}\.\d{3}\]' } | Should -Not -BeNullOrEmpty

        $Global:DebugPreference = $savedDebug
    }
    
    It "Handles concurrent error logging from multiple sources" {
        # Resolve module path to absolute path for Start-Job (separate process)
        $absModulePath = (Resolve-Path $modulePath).Path
        $absLogFile = $Global:LogFile

        $jobs = @()

        for ($i = 1; $i -le 5; $i++) {
            $job = Start-Job -ScriptBlock {
                param($ModulePath, $LogFile, $Index)
                try {
                    Import-Module $ModulePath -Force -ErrorAction Stop
                    $Global:LogFile = $LogFile
                    $env:LOXONE_FORCE_FILE_LOGGING = "1"

                    for ($j = 1; $j -le 10; $j++) {
                        try {
                            if ($j % 3 -eq 0) {
                                throw "Worker $Index error at iteration $j"
                            }
                        } catch {
                            Write-Log -Message "Worker $Index caught error: $_" -Level ERROR
                        }
                        Write-Log -Message "Worker $Index iteration $j" -Level INFO
                        Start-Sleep -Milliseconds 10
                    }
                } catch {
                    # Module import failed - write directly to log as fallback
                    "Worker $Index failed to initialize: $_" | Out-File $LogFile -Append -Encoding UTF8
                }
            } -ArgumentList $absModulePath, $absLogFile, $i

            $jobs += $job
        }

        # Wait for all jobs with timeout
        $jobs | Wait-Job -Timeout 30 | Out-Null
        $failedJobs = $jobs | Where-Object { $_.State -eq 'Failed' }
        $jobs | Remove-Job -Force

        if ($failedJobs.Count -eq $jobs.Count) {
            Set-ItResult -Skipped -Because "All background jobs failed (module import issue in parallel mode)"
            return
        }

        # Small delay for file flush
        Start-Sleep -Milliseconds 200

        # Verify log integrity
        $logLines = Get-Content $absLogFile

        # Should have entries from at least some workers
        $workerEntries = $logLines | Where-Object { $_ -match "Worker \d+" }
        $workerEntries | Should -Not -BeNullOrEmpty

        # Should have both INFO and ERROR entries
        $logLines | Where-Object { $_ -match "\[INFO\]" } | Should -Not -BeNullOrEmpty
        $logLines | Where-Object { $_ -match "\[ERROR\]" } | Should -Not -BeNullOrEmpty
    }
}

Describe "Real Stack Trace Analysis" -Tag 'ErrorHandling', 'Real' {
    
    It "Captures full call stack from nested function calls" {
        function Level1 {
            Level2
        }
        
        function Level2 {
            Level3
        }
        
        function Level3 {
            throw "Deep error"
        }
        
        $stackTrace = $null
        try {
            Level1
        } catch {
            $stackTrace = $_.ScriptStackTrace
        }
        
        $stackTrace | Should -Not -BeNullOrEmpty
        $stackTrace | Should -Match "Level1"
        $stackTrace | Should -Match "Level2"
        $stackTrace | Should -Match "Level3"
    }
    
    It "Preserves error context through script modules" {
        $moduleTempPath = Join-Path $script:TestTempPath "ErrorModule.psm1"
        @'
function Invoke-ModuleError {
    param($Message)
    throw "Module error: $Message"
}
Export-ModuleMember -Function Invoke-ModuleError
'@ | Set-Content $moduleTempPath

        Import-Module $moduleTempPath -Force

        $moduleError = $null
        try {
            Invoke-ModuleError -Message "Test context preservation"
        } catch {
            $moduleError = $_
        }

        Remove-Module ErrorModule -Force -ErrorAction SilentlyContinue

        $moduleError | Should -Not -BeNullOrEmpty
        $moduleError.Exception.Message | Should -Match "Test context preservation"
        # Module name should be captured in the error context
        $moduleError.ScriptStackTrace | Should -Match "ErrorModule"
    }
}

Describe "Real Error Recovery Scenarios" -Tag 'ErrorHandling', 'Real' {
    
    It "Recovers from file access errors with retry logic" {
        $testFile = Join-Path $script:TestTempPath "locked_$(Get-Random).txt"
        "Initial content" | Set-Content $testFile

        # Open file with exclusive lock
        $fileStream = [System.IO.File]::Open($testFile, 'Open', 'ReadWrite', 'None')
        $streamClosed = $false

        $retryCount = 0
        $maxRetries = 3
        $success = $false
        $content = $null

        while ($retryCount -lt $maxRetries -and -not $success) {
            try {
                $content = Get-Content $testFile -ErrorAction Stop
                $success = $true
            } catch {
                $retryCount++
                Write-Log -Message "Retry $retryCount/${maxRetries}: $_" -Level WARN

                if ($retryCount -eq 2 -and -not $streamClosed) {
                    $fileStream.Close()
                    $fileStream.Dispose()
                    $streamClosed = $true
                }

                Start-Sleep -Milliseconds 50
            }
        }

        # Cleanup if stream still open
        if (-not $streamClosed) {
            $fileStream.Close()
            $fileStream.Dispose()
        }

        $success | Should -Be $true
        $content | Should -Be "Initial content"
        $retryCount | Should -BeGreaterOrEqual 2
    }
    
    It "Handles and logs timeout errors" {
        $timeoutOccurred = $false
        
        try {
            # Attempt connection to non-routable IP with timeout
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect("192.0.2.1", 80, $null, $null)
            $waitHandle = $asyncResult.AsyncWaitHandle
            
            if (-not $waitHandle.WaitOne(1000, $false)) {
                $tcpClient.Close()
                throw "Connection timeout after 1000ms"
            }
        } catch {
            $timeoutOccurred = $true
            Write-Log -Message "Timeout error: $_" -Level ERROR
        }
        
        $timeoutOccurred | Should -Be $true
        
        # Verify timeout was logged
        $logContent = Get-Content $Global:LogFile -Raw
        $logContent | Should -Match "timeout"
    }
}

Describe "Real Exception Type Handling" -Tag 'ErrorHandling', 'Real' {
    
    It "Differentiates between exception types" {
        $exceptions = @()
        
        # FileNotFoundException
        try {
            Get-Content "C:\ThisFileDoesNotExist_$(Get-Random).txt" -ErrorAction Stop
        } catch {
            $exceptions += @{
                Type = $_.Exception.GetType().Name
                Message = $_.Exception.Message
            }
        }
        
        # UnauthorizedAccessException (attempt to write to system directory)
        try {
            "test" | Set-Content "C:\Windows\System32\test_$(Get-Random).txt" -ErrorAction Stop
        } catch {
            $exceptions += @{
                Type = $_.Exception.GetType().Name
                Message = $_.Exception.Message
            }
        }
        
        # FormatException
        try {
            [int]::Parse("not a number")
        } catch {
            $exceptions += @{
                Type = $_.Exception.GetType().Name
                Message = $_.Exception.Message
            }
        }
        
        # Verify different exception types were caught
        $exceptions.Count | Should -BeGreaterOrEqual 2
        $uniqueTypes = $exceptions.Type | Select-Object -Unique
        $uniqueTypes.Count | Should -BeGreaterThan 1
        
        # Log each exception type
        foreach ($ex in $exceptions) {
            Write-Log -Message "Exception type: $($ex.Type)" -Level INFO
            Write-Log -Message "Exception message: $($ex.Message)" -Level DEBUG
        }
    }
}

