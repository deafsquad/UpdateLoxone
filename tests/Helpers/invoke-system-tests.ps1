# Helper script to run RunAsUser tests as SYSTEM and return results
# This can be called from other test scripts to get SYSTEM test results

param(
    [string]$PsExecPath,
    [switch]$Quiet
)

# Must be admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    if (-not $Quiet) {
        Write-Warning "Not running as Administrator. Cannot run SYSTEM tests."
    }
    return @{
        Success = $false
        Error = "Administrator privileges required"
        Results = $null
    }
}

# Find PsExec if not provided
if (-not $PsExecPath -or -not (Test-Path $PsExecPath)) {
    $locations = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Microsoft.Sysinternals_Microsoft.Winget.Source_8wekyb3d8bbwe\PsExec.exe",
        "$env:TEMP\PsExec.exe",
        "$env:TEMP\PsExec64.exe",
        "C:\Tools\PsExec.exe",
        "C:\Tools\PsExec64.exe"
    )
    
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            $PsExecPath = $loc
            break
        }
    }
    
    if (-not $PsExecPath) {
        # Try to find psexec in PATH (case insensitive)
        $cmd = Get-Command psexec -ErrorAction SilentlyContinue
        if (-not $cmd) {
            $cmd = Get-Command psexec.exe -ErrorAction SilentlyContinue
        }
        if (-not $cmd) {
            $cmd = Get-Command PsExec -ErrorAction SilentlyContinue
        }
        if (-not $cmd) {
            $cmd = Get-Command PsExec.exe -ErrorAction SilentlyContinue
        }
        if ($cmd) { 
            $PsExecPath = $cmd.Source 
        }
    }
}

if (-not $PsExecPath -or -not (Test-Path $PsExecPath)) {
    return @{
        Success = $false
        Error = "PsExec not found"
        Results = $null
    }
}

# Get project root path - go up two levels from Helpers folder
$projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Create temp folder in tests directory
$testTempPath = Join-Path $PSScriptRoot "temp"
# Clean up any previous test files first
if (Test-Path $testTempPath) {
    Get-ChildItem -Path $testTempPath -Filter "runasuser-system-test-*.json" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $testTempPath -Filter "system-test-runner-*.ps1" | Remove-Item -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $testTempPath)) {
    New-Item -ItemType Directory -Path $testTempPath -Force | Out-Null
}

# Create inline test script with dynamic paths
$testScript = @"
`$ErrorActionPreference = 'Stop'
`$testTempPath = "$testTempPath"
`$resultsFile = Join-Path "`$testTempPath" "runasuser-system-test-`$(Get-Date -Format 'yyyyMMddHHmmss').json"

try {
    # Load modules
    Import-Module "$projectRoot\LoxoneUtils\LoxoneUtils.Logging.psm1" -Force
    Import-Module "$projectRoot\LoxoneUtils\LoxoneUtils.Utility.psm1" -Force
    Import-Module "$projectRoot\LoxoneUtils\LoxoneUtils.RunAsUser.psm1" -Force
    
    # Set up environment
    `$Global:LogFile = Join-Path "`$testTempPath" "runasuser-test.log"
    
    # Test 1: Simple execution
    `$test1Success = `$false
    `$test1Error = `$null
    `$test1Result = `$null
    try {
        `$result = Invoke-AsCurrentUser -ScriptBlock { 
            "Test from `$env:USERNAME at `$(Get-Date -Format HH:mm:ss)" 
        } -CaptureOutput
        `$test1Result = `$result
        `$test1Success = `$result -match "Test from"
        if (-not `$test1Success) {
            `$test1Error = "Expected 'Test from' but got: '`$result'"
        }
    } catch { 
        `$test1Error = `$_.Exception.Message
    }
    
    # Test 2: Verify context switch
    `$test2Success = `$false
    `$test2Error = `$null
    `$test2Result = `$null
    try {
        `$result = Invoke-AsCurrentUser -ScriptBlock {
            `$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            "`$(`$id.Name)|`$(`$id.IsSystem)"
        } -CaptureOutput
        `$test2Result = `$result
        `$test2Success = `$result -match "False" # Should not be SYSTEM
        if (-not `$test2Success) {
            `$test2Error = "Expected 'False' (not SYSTEM) but got: '`$result'"
        }
    } catch { 
        `$test2Error = `$_.Exception.Message
    }
    
    # Test 3: NoWait
    `$test3Success = `$false
    `$test3Error = `$null
    try {
        `$result = Invoke-AsCurrentUser -ScriptBlock { "Async" } -NoWait
        `$test3Success = `$result -match "^\d+`$" # Should return PID
    } catch { 
        `$test3Error = `$_.Exception.Message
    }
    
    # Test 4: File execution
    `$test4Success = `$false
    `$test4Error = `$null
    try {
        `$testBat = Join-Path "`$testTempPath" "test-`$([guid]::NewGuid()).bat"
        "@echo off`necho OK" | Out-File `$testBat -Encoding ASCII
        `$result = Invoke-AsCurrentUser -FilePath "cmd.exe" -Arguments "/c ```"`$testBat```"" -CaptureOutput
        Remove-Item `$testBat -Force -ErrorAction SilentlyContinue
        `$test4Success = `$result -match "OK"
    } catch { 
        `$test4Error = `$_.Exception.Message
    }
    
    # Summary
    `$results = @{
        Success = `$true
        TotalTests = 4
        PassedTests = @(`$test1Success, `$test2Success, `$test3Success, `$test4Success).Where({ `$_ }).Count
        Test1_SimpleExecution = `$test1Success
        Test1_Error = `$test1Error
        Test1_Result = `$test1Result
        Test2_ContextSwitch = `$test2Success
        Test2_Error = `$test2Error
        Test2_Result = `$test2Result
        Test3_NoWait = `$test3Success
        Test3_Error = `$test3Error
        Test4_FileExecution = `$test4Success
        Test4_Error = `$test4Error
        ExecutedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}
catch {
    `$results = @{
        Success = `$false
        Error = `$_.Exception.Message
        TotalTests = 4
        PassedTests = 0
    }
}

`$results | ConvertTo-Json -Depth 10 | Out-File -FilePath `$resultsFile -Encoding UTF8
Write-Output `$resultsFile
"@

# Save script
$scriptPath = Join-Path $testTempPath "system-test-runner-$(Get-Date -Format 'yyyyMMddHHmmss').ps1"
$testScript | Out-File -FilePath $scriptPath -Encoding UTF8

try {
    # Run as SYSTEM
    if (-not $Quiet) {
        Write-Host "Running RunAsUser functional tests as SYSTEM..." -ForegroundColor Cyan
        Write-Host "Using PsExec at: $PsExecPath" -ForegroundColor Gray
    }
    
    # Use Start-Process for better output control
    $outputFile = Join-Path $testTempPath "psexec-output-$(Get-Date -Format 'yyyyMMddHHmmss').txt"
    $errorFile = Join-Path $testTempPath "psexec-error-$(Get-Date -Format 'yyyyMMddHHmmss').txt"
    
    $psexecProcess = Start-Process -FilePath $PsExecPath -ArgumentList @(
        "-accepteula",
        "-s",
        "-nobanner",
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`""
    ) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
    
    # Read output
    $output = @()
    if (Test-Path $outputFile) {
        $output = Get-Content $outputFile
        Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
    }
    
    # Debug output if not quiet
    if (-not $Quiet) {
        if (Test-Path $errorFile) {
            $stderr = Get-Content $errorFile
            if ($stderr) {
                Write-Host "PsExec stderr:" -ForegroundColor Gray
                $stderr | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }
        }
        if ($output) {
            Write-Host "PsExec stdout:" -ForegroundColor Gray
            $output | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        }
    }
    
    Remove-Item $errorFile -Force -ErrorAction SilentlyContinue
    
    # Extract the last line which should be the results file path
    $lastLine = $output | Where-Object { $_ } | Select-Object -Last 1
    if ($lastLine) {
        $resultsFile = $lastLine.Trim()
    } else {
        # If no output, check if PsExec is working
        # PsExec outputs its messages to stderr, we need to check exit code
        $testOutputFile = Join-Path $testTempPath "psexec-test.txt"
        $testErrorFile = Join-Path $testTempPath "psexec-test-err.txt"
        $testCmd = Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula", "-nobanner", "cmd", "/c", "echo test" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $testOutputFile -RedirectStandardError $testErrorFile
        
        $testSucceeded = $false
        if ($testCmd.ExitCode -eq 0) {
            # Check if the output file contains "test"
            if (Test-Path $testOutputFile) {
                $testContent = Get-Content $testOutputFile -Raw
                if ($testContent -match "test") {
                    $testSucceeded = $true
                }
                Remove-Item $testOutputFile -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item $testErrorFile -Force -ErrorAction SilentlyContinue
        
        if (-not $testSucceeded) {
            throw "PsExec not functioning properly. Exit code: $($testCmd.ExitCode). Path: $PsExecPath"
        } else {
            # PsExec works, but script output was not captured
            # This might be due to permission issues or script errors
            throw "No output received from SYSTEM test execution. Script may have failed to run. Check script path and permissions."
        }
    }
    
    if (Test-Path $resultsFile) {
        $results = Get-Content $resultsFile -Raw | ConvertFrom-Json
        # Files are cleaned up at the beginning of next run for investigation
        
        if (-not $Quiet) {
            Write-Host "SYSTEM test results: $($results.PassedTests)/$($results.TotalTests) passed" -ForegroundColor $(if ($results.PassedTests -eq $results.TotalTests) { 'Green' } else { 'Yellow' })
        }
        
        return @{
            Success = $true
            Results = $results
        }
    }
    else {
        return @{
            Success = $false
            Error = "Results file not created"
            Results = $null
        }
    }
}
catch {
    return @{
        Success = $false
        Error = $_.Exception.Message
        Results = $null
    }
}
finally {
    # Cleanup
    if (Test-Path $scriptPath) {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }
}