<#
.SYNOPSIS
Runs tests against functions in the UpdateLoxoneUtils.psm1 module.
Runs tests non-elevated first, then attempts an elevated run by default.
Displays a combined summary at the end. Use -SkipElevation to prevent the elevated run.
#>
[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Specify test categories (Logging, Version, Utils, Process, Task, Notifications, Admin), specific function names (e.g., 'Register-ScheduledTaskForScript'), or 'All' to run.")]
    [string[]]$TestName = "All", 

    [Parameter(HelpMessage="Skips the attempt to run tests in an elevated context.")]
    [switch]$SkipElevation = $false,

    # Add specific paths if needed for testing, defaults are determined below
    [Parameter()]
    [string]$TestScriptSaveFolder,

    [Parameter()]
    [string]$TestLogFile,

    # Internal switch to indicate this is the relaunched elevated instance
    [Parameter(DontShow=$true)]
    [switch]$IsElevatedInstance = $false,

    # Internal param for elevated instance to write results
    [Parameter(DontShow=$true)]
    [string]$ElevatedOutputFile 
)

# --- Initial Setup ---
$script:StartTime = Get-Date
Write-Host "Starting Test Run at $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"

# Determine Script Directory (more robustly)
if ($PSScriptRoot) { $scriptDir = $PSScriptRoot } 
else { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition -ErrorAction SilentlyContinue }
if (-not $scriptDir -or -not (Test-Path $scriptDir)) { Write-Error "Could not determine script directory."; exit 1 }

# Set default paths if not provided
if (-not $PSBoundParameters.ContainsKey('TestScriptSaveFolder')) { $TestScriptSaveFolder = $scriptDir }
if (-not $PSBoundParameters.ContainsKey('TestLogFile')) { $TestLogFile = Join-Path -Path $TestScriptSaveFolder -ChildPath "Test-UpdateLoxone.log" }

# Determine Module Path
$modulePath = Join-Path -Path $scriptDir -ChildPath "UpdateLoxoneUtils.psm1"

# --- Global Variables & Initial Cleanup ---
$script:DebugMode = $true 
$VerbosePreference = "Continue" 
$global:LogFile = $TestLogFile 
$script:ScriptSaveFolder = $TestScriptSaveFolder 
$script:ScheduledTaskIntervalMinutes = 10 
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:IsElevatedRun = $isAdmin # Flag for use within tests

# Clean up previous test log only if NOT the elevated instance
if (-not $IsElevatedInstance -and (Test-Path $global:LogFile)) { 
    Write-Host "Cleaning up previous test log: $global:LogFile"
    Remove-Item $global:LogFile -Force 
}

# Import the module (needs to happen in both instances)
try {
    Write-Host "Importing module: $modulePath"
    Import-Module -Name $modulePath -Force -ErrorAction Stop
    Write-Host "Module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "FATAL: Could not import utility module '$modulePath'. Tests cannot run. Error: $($_.Exception.Message)"
    exit 1
}

# --- Helper Functions ---
# Helper function to determine if a specific test should run
function Test-ShouldRun { # Renamed function
    param( [string]$IndividualTestName, [string]$CategoryName )
    # Access $TestName from the outer script scope
    return ($script:TestName -contains "All" -or $script:TestName -contains $IndividualTestName -or $script:TestName -contains $CategoryName)
}

# Helper function for running tests
function Invoke-Test { # Renamed function
    param( [string]$Name, [scriptblock]$TestBlock )
    
    Write-Host "Running Test: $Name" -ForegroundColor White
    $testPassed = $false; $errorMessage = $null
    try {
        $result = & $TestBlock
            if ($LASTEXITCODE -eq 0 -or $? -eq $true) {
                 if ($result -is [bool] -and (-not $result)) {
                     $testPassed = $false; $errorMessage = "Test block returned false."
                 } else { $testPassed = $true }
            } else { $errorMessage = "Test block failed (LASTEXITCODE: $LASTEXITCODE, Error: $($Error[0].ToString()))"; $testPassed = $false }
        } 
        catch {
            $errorMessage = "Exception during test: $($_.Exception.Message)"
            $testPassed = $false
        } 
        finally {
            # Empty finally block - no cleanup needed for individual tests for now
        }

        if ($testPassed) {
            Write-Host "  Result: PASS" -ForegroundColor Green
            $script:currentTestSuiteResults[$Name] = "PASS" } 
        else {
            Write-Host "  Result: FAIL" -ForegroundColor Red
            if ($errorMessage) {
                Write-Host "    Reason: $errorMessage" -ForegroundColor Red
            }
            $script:currentTestSuiteResults[$Name] = "FAIL"
            $script:currentTestSuiteOverallResult = $false # Update script-scoped overall result for the current suite
        }
        Write-Host 
    }

# --- Test Execution Function ---
function Invoke-TestSuite {
    param(
        [bool]$IsTaskContext,
        [bool]$IsCurrentlyElevated # Pass current elevation status
    )
    $contextType = if ($IsCurrentlyElevated) { "Elevated" } else { "Non-Elevated" }
    $simType = if ($IsTaskContext) { "Simulated Task" } else { "Normal" }
    Write-Host "`n--- Running Tests ($simType Context - $contextType) ---" -ForegroundColor Cyan
    
    $script:SimulateTask = $IsTaskContext # Set simulation flag for this run

    $script:currentTestSuiteResults = @{} # Use script scope for results within this suite run
    $script:currentTestSuiteOverallResult = $true # Use script scope for overall result of this suite run

    # --- Define Test Cases ---
    if (Test-ShouldRun -CategoryName "Logging" -IndividualTestName "Write-LogMessage") {
        Invoke-Test -Name "Write-LogMessage (INFO)" -TestBlock { Write-LogMessage -Message "Test INFO message (Context: $simType $contextType)" -Level "INFO"; return (Select-String -Path $global:LogFile -Pattern "Test INFO message \(Context: $simType $contextType\)" -Quiet) }
        Invoke-Test -Name "Write-LogMessage (ERROR)" -TestBlock { Write-LogMessage -Message "Test ERROR message (Context: $simType $contextType)" -Level "ERROR"; return (Select-String -Path $global:LogFile -Pattern "Test ERROR message \(Context: $simType $contextType\)" -Quiet) }
    }
    if (Test-ShouldRun -CategoryName "Logging" -IndividualTestName "Invoke-LogFileRotation") {
         Invoke-Test -Name "Invoke-LogFileRotation" -TestBlock { Set-Content -Path $global:LogFile -Value "Dummy log content $(Get-Random)"; Invoke-LogFileRotation -LogPath $global:LogFile -MaxArchives 1; $archiveExists = Get-ChildItem -Path $script:TestScriptSaveFolder -Filter "Test-UpdateLoxone_*.log" | Measure-Object | Select-Object -ExpandProperty Count; $originalGone = -not (Test-Path $global:LogFile); Get-ChildItem -Path $script:TestScriptSaveFolder -Filter "Test-UpdateLoxone_*.log" | Remove-Item -Force -ErrorAction SilentlyContinue; return $originalGone -and ($archiveExists -ge 1) }
    }
    if (Test-ShouldRun -CategoryName "Version" -IndividualTestName "Convert-VersionString") {
         Invoke-Test -Name "Convert-VersionString" -TestBlock { $v1 = "10.1.2.3"; $v2 = "15.6.04.01"; $norm1 = Convert-VersionString $v1; $norm2 = Convert-VersionString $v2; return ($norm1 -eq "10.1.2.3") -and ($norm2 -eq "15.6.4.1") }
    }
    if (Test-ShouldRun -CategoryName "Utils" -IndividualTestName "Get-RedactedPassword") {
         Invoke-Test -Name "Get-RedactedPassword" -TestBlock { $url1 = "http://user:password@host.com"; $url2 = "https://admin:12345@192.168.1.1"; $redacted1 = Get-RedactedPassword $url1; $redacted2 = Get-RedactedPassword $url2; return ($redacted1 -eq "http://user:********@host.com") -and ($redacted2 -eq "https://admin:********@192.168.1.1") }
    }
    if (Test-ShouldRun -CategoryName "Utils" -IndividualTestName "Save-ScriptToUserLocation") {
        Invoke-Test -Name "Save-ScriptToUserLocation" -TestBlock { 
            # Setup: Create a dummy source script file to copy
            $dummySourceName = "DummySourceForSaveTest.ps1"
            $dummySourcePath = Join-Path -Path $script:TestScriptSaveFolder -ChildPath $dummySourceName
            Set-Content -Path $dummySourcePath -Value "# Test Source Content $(Get-Random)" -Force
            
            $tempDestDir = Join-Path -Path $script:TestScriptSaveFolder -ChildPath "TempTestSaveFolder"
            $tempDestFile = Join-Path -Path $tempDestDir -ChildPath $dummySourceName # Expecting dummy file name
            if (Test-Path $tempDestDir) { Remove-Item -Path $tempDestDir -Recurse -Force }

            # Execute: Call the function to copy the dummy script using the -SourcePath parameter
            $resultPath = $null
            try {
                 $resultPath = Save-ScriptToUserLocation -DestinationDir $tempDestDir -ScriptName $dummySourceName -SourcePath $dummySourcePath -ErrorAction Stop
            } catch {
                 Write-Warning "Save-ScriptToUserLocation test failed during execution: $($_.Exception.Message)"
                 # Let validation fail below
            }
            
            # Validate: Check if function returned correct path, file exists, and is not empty
            $fileExists = Test-Path -Path $tempDestFile
            $fileNotEmpty = $false
            if ($fileExists) {
                 $fileSize = (Get-Item -Path $tempDestFile).Length
                 if ($fileSize -gt 0) { $fileNotEmpty = $true } else { Write-Warning "Copied file '$tempDestFile' is empty." }
            } else { Write-Warning "Copied file '$tempDestFile' not found." }
            $pathMatches = ($resultPath -eq $tempDestFile)
            if (-not $pathMatches) { Write-Warning "Save-ScriptToUserLocation returned incorrect path. Expected: '$tempDestFile', Got: '$resultPath'" }

            # Cleanup
            if (Test-Path $tempDestDir) { Remove-Item -Path $tempDestDir -Recurse -Force }
            Remove-Item -Path $dummySourcePath -Force -ErrorAction SilentlyContinue # Cleanup dummy source

            # Return result
            return ($fileExists -and $fileNotEmpty -and $pathMatches)
        }
    }
    if (Test-ShouldRun -CategoryName "Process" -IndividualTestName "Get-ProcessStatus") {
        Invoke-Test -Name "Get-ProcessStatus (Notepad Running/Stopped)" -TestBlock { $proc = Start-Process notepad -PassThru -ErrorAction SilentlyContinue; if (-not $proc) { throw "Failed to start notepad for test." }; Start-Sleep -Seconds 1; $isRunning = Get-ProcessStatus -ProcessName "notepad"; $stopResult = Get-ProcessStatus -ProcessName "notepad" -StopProcess; Start-Sleep -Seconds 1; $isStopped = Get-ProcessStatus -ProcessName "notepad"; if (-not $isRunning) { Write-Warning "Get-ProcessStatus failed to detect running process."; return $false }; if (-not $stopResult) { Write-Warning "Get-ProcessStatus failed to report stop success."; return $false }; if ($isStopped) { Write-Warning "Get-ProcessStatus failed to detect stopped process."; return $false }; return $true }
    }
    if (Test-ShouldRun -CategoryName "Task" -IndividualTestName "Test-ScheduledTask") {
         Invoke-Test -Name "Test-ScheduledTask (Context: $simType)" -TestBlock { $originalFunc = $null; if ($script:SimulateTask) { $originalFunc = Get-Command Test-ScheduledTask; $mockFunc = [scriptblock]::Create('$true'); Set-Item Function:\Test-ScheduledTask -Value $mockFunc }; $result = $null; try { $result = Test-ScheduledTask } finally { if ($originalFunc) { Set-Item Function:\Test-ScheduledTask -Value $originalFunc.ScriptBlock } }; if ($script:SimulateTask) { return $result } else { return (-not $result) } }
    }
    if (Test-ShouldRun -CategoryName "Notifications" -IndividualTestName "Show-NotificationToLoggedInUsers") {
        Invoke-Test -Name "Show-NotificationToLoggedInUsers (Context: $simType)" -TestBlock { $originalFunc = Get-Command Test-ScheduledTask; $mockFunc = [scriptblock]::Create('$script:SimulateTask'); Set-Item Function:\Test-ScheduledTask -Value $mockFunc; try { Show-NotificationToLoggedInUsers -Title "Test Notification" -Message "Context Test ($simType $contextType)" } finally { Set-Item Function:\Test-ScheduledTask -Value $originalFunc.ScriptBlock }; if ($script:SimulateTask) { return -not (Select-String -Path $global:LogFile -Pattern "Attempting notification via scheduled task method." -Quiet) } else { return (Select-String -Path $global:LogFile -Pattern "Running interactively. Attempting direct notification." -Quiet) } }
    }
    # Add tests that require Elevation (will fail if not elevated)
    if (Test-ShouldRun -CategoryName "Admin" -IndividualTestName "Register-ScheduledTaskForScript") {
        Invoke-Test -Name "Register-ScheduledTaskForScript (Requires Elevation)" -TestBlock { $testTaskName = "TestLoxoneUpdateTask_$(Get-Random)"; $dummyScriptPath = Join-Path $script:TestScriptSaveFolder "dummy.ps1"; Set-Content -Path $dummyScriptPath -Value "# Dummy" -Force; $success = $true; try { Register-ScheduledTaskForScript -ScriptPath $dummyScriptPath -TaskName $testTaskName -ScheduledTaskIntervalMinutes $script:ScheduledTaskIntervalMinutes -Channel "Test" -DebugMode $script:DebugMode -EnableCRC $true -InstallMode "verysilent" -CloseApplications $false -ScriptSaveFolder $script:ScriptSaveFolder -MaxLogFileSizeMB 1 -SkipUpdateIfAnyProcessIsRunning $false; if ($script:IsElevatedRun -and -not (Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue)) { $success = $false; Write-Warning "Scheduled task '$testTaskName' was not created even when elevated." } elseif (-not $script:IsElevatedRun -and (Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue)) { $success = $false; Write-Warning "Scheduled task '$testTaskName' was created unexpectedly without elevation." } elseif (-not $script:IsElevatedRun) { Write-Host "  INFO: Task registration correctly failed (not elevated)." -ForegroundColor Gray; $success = $true } } catch { if (-not $script:IsElevatedRun) { Write-Host "  INFO: Task registration correctly failed with error (not elevated): $($_.Exception.Message)" -ForegroundColor Gray; $success = $true } else { $success = $false; Write-Warning "Error during Register-ScheduledTaskForScript test (Elevated): $($_.Exception.Message)" } } finally { Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue; if (Test-Path $dummyScriptPath) { Remove-Item -Path $dummyScriptPath -Force -ErrorAction SilentlyContinue } }; return $success }
    }

    # Return results for this run
    return @{ Result = $script:currentTestSuiteOverallResult; Details = $script:currentTestSuiteResults } 
} # End of Invoke-TestSuite function

# --- Main Execution Logic ---
$allNonElevatedResults = @{}
$nonElevatedPass = $true
$elevatedSummary = $null
$elevatedExitCode = 0 # Assume success unless elevation fails or is skipped

# --- Run Non-Elevated Tests (Always run if this is the initial instance) ---
if (-not $IsElevatedInstance) {
    Write-Host "`n=== Running Non-Elevated Tests ===" -ForegroundColor Yellow
    $normalRun = Invoke-TestSuite -IsTaskContext $false -IsCurrentlyElevated $false
    $allNonElevatedResults["Normal Context (Non-Elevated)"] = $normalRun
    if (-not $normalRun.Result) { $nonElevatedPass = $false }

    $taskRun = Invoke-TestSuite -IsTaskContext $true -IsCurrentlyElevated $false
    $allNonElevatedResults["Simulated Task Context (Non-Elevated)"] = $taskRun
    if (-not $taskRun.Result) { $nonElevatedPass = $false }

    # --- Attempt Elevated Run ---
    if (-not $SkipElevation -and -not $isAdmin) {
        Write-Warning "`nAttempting to relaunch script with elevated privileges..."
        $tempOutputFile = [System.IO.Path]::GetTempFileName()
        Write-Host "Elevated process will write summary to: $tempOutputFile"
        $relaunchArgsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$($MyInvocation.MyCommand.Path)`"")
        $PSBoundParameters.Keys | Where-Object { $_ -ne 'SkipElevation' } | ForEach-Object { 
            $paramName = $_; $paramValue = $PSBoundParameters[$paramName]
            if ($paramValue -is [System.Management.Automation.SwitchParameter]) { if ($paramValue.IsPresent) { $relaunchArgsList += "-$paramName" } }
            else { $relaunchArgsList += "-$paramName", """$paramValue`"" }
        }
        $relaunchArgsList += "-IsElevatedInstance"; $relaunchArgsList += "-ElevatedOutputFile", """$tempOutputFile"""
        $relaunchArgs = $relaunchArgsList -join " "
        Write-Host "Relaunch Args: $relaunchArgs"
        $process = $null
        try {
             $process = Start-Process -FilePath "PowerShell.exe" -ArgumentList $relaunchArgs -Verb RunAs -WindowStyle Normal -Wait -PassThru -ErrorAction Stop
             $elevatedExitCode = $process.ExitCode
             Write-Host "Elevated process finished with Exit Code: $elevatedExitCode." -ForegroundColor Gray
             if (Test-Path $tempOutputFile) { $elevatedSummary = Get-Content -Path $tempOutputFile -Raw; Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue } 
             else { Write-Warning "Elevated output file not found: $tempOutputFile" }
             # Don't set overallPass based on elevatedExitCode here, do it in final summary
        } catch { Write-Error "Failed to re-launch script as Admin: $($_.Exception.Message)."; if (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }; $elevatedExitCode = 1; $elevatedSummary = "`n--- Elevated Run FAILED to Start ---`nError: $($_.Exception.Message)`n" }
    } elseif ($SkipElevation) {
        Write-Host "`n--- Elevated Run Skipped ---" -ForegroundColor Yellow
    } elseif ($isAdmin) {
         Write-Warning "`nScript is already running elevated. Cannot run separate non-elevated tests first in this mode."
         # If started as admin, the first run *was* the elevated run. We store its results for the combined summary.
         $elevatedSummary = @"
`n--- Test Summary (Elevated - Started Directly) ---
"@
         $totalPass = 0; $totalFail = 0
         foreach ($contextKey in $allNonElevatedResults.Keys) { # Use results collected in this instance
             $contextRun = $allNonElevatedResults[$contextKey]
             $summaryOutputElevated = "Context: $contextKey`n" # Use different var name
             $contextResults = $contextRun.Details
             if ($null -ne $contextResults) {
                 $contextPass = ($contextResults.Values | Where-Object { $_ -eq "PASS" }).Count
                 $contextFail = ($contextResults.Values | Where-Object { $_ -eq "FAIL" }).Count
                 $totalPass += $contextPass; $totalFail += $contextFail
                 $summaryOutputElevated += "  Passed: $contextPass`n"
                 $summaryOutputElevated += "  Failed: $contextFail`n"
                 $contextResultText = if (-not $contextRun.Result) { "FAIL" } else { "PASS" }
                 $summaryOutputElevated += "  Context Result: $contextResultText`n"
             } else { $summaryOutputElevated += "  No results recorded for this context.`n" }
             $elevatedSummary += $summaryOutputElevated
         }
         $elevatedSummary += "--------------------------`n"
         $elevatedSummary += "Total Tests Run (Elevated): $($totalPass + $totalFail)`n"
         $elevatedSummary += "Total Passed (Elevated): $totalPass`n"
         $elevatedSummary += "Total Failed (Elevated): $totalFail`n"
         $overallResultText = if ($nonElevatedPass) { 'PASS' } else { 'FAIL' } # Use this instance's pass status
         $elevatedSummary += "Overall Result for Elevated Context: $overallResultText`n"
         $elevatedExitCode = if ($nonElevatedPass) { 0 } else { 1 } # Set exit code based on this run
    }

    # --- Display FINAL Combined Summary (from Non-Elevated Instance) ---
    Write-Host "`n=== Combined Test Summary ===" -ForegroundColor Cyan
    
    # Display Non-Elevated Results
    Write-Host "--- Results from Non-Elevated Run ---" -ForegroundColor Cyan
    $totalNonElevatedPass = 0; $totalNonElevatedFail = 0
    foreach ($contextKey in $allNonElevatedResults.Keys) {
        $contextRun = $allNonElevatedResults[$contextKey]
        Write-Host "Context: $contextKey" -ForegroundColor White
        $contextResults = $contextRun.Details
        if ($null -ne $contextResults) {
            $contextPass = ($contextResults.Values | Where-Object { $_ -eq "PASS" }).Count
            $contextFail = ($contextResults.Values | Where-Object { $_ -eq "FAIL" }).Count
            $totalNonElevatedPass += $contextPass; $totalNonElevatedFail += $contextFail
            Write-Host "  Passed: $contextPass"
            Write-Host "  Failed: $contextFail"
            $contextResultText = if (-not $contextRun.Result) { "FAIL" } else { "PASS" }
            $fgColor = if ($contextRun.Result) { "Green" } else { "Red" }
            Write-Host "  Context Result: $contextResultText" -ForegroundColor $fgColor
        } else { Write-Host "  No results recorded for this context." -ForegroundColor Yellow }
    }
    Write-Host "--------------------------"
    Write-Host "Total Non-Elevated Passed: $totalNonElevatedPass"
    Write-Host "Total Non-Elevated Failed: $totalNonElevatedFail"
    $overallNonElevatedResultText = if ($nonElevatedPass) { 'PASS' } else { 'FAIL' }
    $overallNonElevatedColor = if ($nonElevatedPass) { "Green" } else { "Red" }
    Write-Host "Overall Non-Elevated Result: $overallNonElevatedResultText" -ForegroundColor $overallNonElevatedColor

    # Display Elevated Results (if available)
    if ($elevatedSummary) {
        Write-Host "`n--- Results from Elevated Run ---" -ForegroundColor Magenta
        Write-Host $elevatedSummary # This summary comes pre-formatted from the elevated instance or generated if started elevated
        Write-Host "--- End Elevated Run Results ---" -ForegroundColor Magenta
    } 
    
    # Determine final overall exit code based on BOTH runs
    $finalOverallPass = $nonElevatedPass -and ($elevatedExitCode -eq 0)
    if ($SkipElevation -and $nonElevatedPass) { $finalOverallPass = $true } # If skipped and non-elevated passed, overall is pass
    if ($isAdmin -and -not $IsElevatedInstance) { $finalOverallPass = $nonElevatedPass } # If started elevated, only non-elevated (which ran elevated) matters

    Write-Host "`nAll test runs complete. Press Enter to exit." -ForegroundColor Yellow
    Read-Host
    
    # --- Cleanup ---
    Write-Host "--- Test Cleanup ---" -ForegroundColor Cyan
    # Optional: Remove test log
    # Remove-Item $global:LogFile -Force -ErrorAction SilentlyContinue
    
    $exitCode = if ($finalOverallPass) { 0 } else { 1 }
    exit $exitCode

} 
# Else (this IS the elevated instance):
else {
    # Run tests for the elevated context
    $elevatedContextResults = @{}
    $elevatedContextPass = $true 

    $elevatedNormalRun = Invoke-TestSuite -IsTaskContext $false -IsCurrentlyElevated $true
    $elevatedContextResults["Normal Context (Elevated)"] = $elevatedNormalRun
    if (-not $elevatedNormalRun.Result) { $elevatedContextPass = $false }

    $elevatedTaskRun = Invoke-TestSuite -IsTaskContext $true -IsCurrentlyElevated $true
    $elevatedContextResults["Simulated Task Context (Elevated)"] = $elevatedTaskRun
    if (-not $elevatedTaskRun.Result) { $elevatedContextPass = $false }

    # Prepare summary output for THIS elevated run
    $summaryOutput = @"
`n--- Test Summary (Elevated) ---
"@
    $totalPass = 0; $totalFail = 0
    foreach ($contextKey in $elevatedContextResults.Keys) { # Use results collected in this instance
        $contextRun = $elevatedContextResults[$contextKey]
        $summaryOutput += "`nContext: $contextKey"
        $contextResults = $contextRun.Details
        if ($null -ne $contextResults) {
            $contextPass = ($contextResults.Values | Where-Object { $_ -eq "PASS" }).Count
            $contextFail = ($contextResults.Values | Where-Object { $_ -eq "FAIL" }).Count
            $totalPass += $contextPass; $totalFail += $contextFail
            $summaryOutput += "`n  Passed: $contextPass"
            $summaryOutput += "`n  Failed: $contextFail"
            $contextResultText = if (-not $contextRun.Result) { "FAIL" } else { "PASS" }
            $summaryOutput += "`n  Context Result: $contextResultText"
        } else { $summaryOutput += "`n  No results recorded for this context." }
    }
    $summaryOutput += "`n--------------------------"
    $summaryOutput += "`nTotal Tests Run (Elevated): $($totalPass + $totalFail)"
    $summaryOutput += "`nTotal Passed (Elevated): $totalPass"
    $summaryOutput += "`nTotal Failed (Elevated): $totalFail"
    $overallResultText = if ($elevatedContextPass) { 'PASS' } else { 'FAIL' } # Use this instance's pass status
    $summaryOutput += "`nOverall Result for Elevated Context: $overallResultText`n"

    # Write summary to output file
    if ($ElevatedOutputFile) {
        try { Write-Host $summaryOutput; Write-Host "Writing summary to elevated output file: $ElevatedOutputFile" -ForegroundColor Gray; Set-Content -Path $ElevatedOutputFile -Value $summaryOutput -Encoding UTF8 -Force -ErrorAction Stop } 
        catch { Write-Warning "Failed to write summary to elevated output file '$ElevatedOutputFile': $($_.Exception.Message)" }
    } else { Write-Warning "ElevatedOutputFile parameter not provided to elevated instance." }
    
    # Pause the elevated window
    Write-Host "`nElevated test run complete. Press Enter in this window to close it." -ForegroundColor Yellow; Read-Host
    
    # Exit with appropriate code based on this instance's results
    $exitCode = if ($elevatedContextPass) { 0 } else { 1 }
    exit $exitCode
}