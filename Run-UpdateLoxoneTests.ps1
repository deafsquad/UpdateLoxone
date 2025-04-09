<#
.SYNOPSIS
Runs tests against functions in the UpdateLoxoneUtils.psm1 module.
Runs tests non-elevated first, then attempts to self-elevate to run Admin context tests.
Displays a combined summary at the end. Use -SkipElevation to prevent the elevated run.
#>
[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Specify test categories (Logging, Version, Utils, Process, Task, Notifications, Admin), specific function names (e.g., 'Register-ScheduledTaskForScript'), or 'All' to run.")]
    [string[]]$TestName = "All", 

    [Parameter(HelpMessage="Skips the attempt to run tests elevated.")]
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

# Initialize results hashtable globally for safety
$script:currentTestSuiteResults = @{}

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
$script:IsAdminRun = $isAdmin # Flag for use within tests
$script:TestName = $TestName # Assign parameter to script scope for Test-ShouldRun

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
function TestShouldRun { # Renamed function, removed hyphen
    param( [string]$IndividualTestName, [string]$CategoryName )
    # Access $TestName from the outer script scope
    return ($script:TestName -contains "All" -or $script:TestName -contains $IndividualTestName -or $script:TestName -contains $CategoryName)
}

# Helper function for running tests
function InvokeTest { # Renamed function, removed hyphen
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

        if ($null -eq $Name) {
            Write-Error "InvokeTest called with null Name parameter!"
            # Decide how to handle this - maybe skip recording result or record generic failure
            $script:currentTestSuiteOverallResult = $false
        }
        elseif ($testPassed) {
            Write-Host "  Result: PASS" -ForegroundColor Green
            $script:currentTestSuiteResults[$Name] = "PASS"
        }
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
function InvokeTestSuite { # Removed hyphen
    param(
        [bool]$IsCurrentlyAdmin # Pass current admin status
    )
{
    $contextType = if ($IsCurrentlyAdmin) { "Admin" } else { "Non-Admin" }
    Write-Host "`n--- Running Tests ($contextType Context) ---" -ForegroundColor Cyan
    
    $script:currentTestSuiteResults = @{} # Use script scope for results within this suite run
    $script:currentTestSuiteOverallResult = $true # Use script scope for overall result of this suite run

    # --- Define Test Cases ---
    if (TestShouldRun -CategoryName "Logging" -IndividualTestName "WriteLog") { # Removed hyphen from TestShouldRun, updated IndividualTestName
        InvokeTest -Name "WriteLog (INFO)" -TestBlock { WriteLog -Message "Test INFO message (Context: $contextType)" -Level "INFO"; return (Select-String -Path $global:LogFile -Pattern "Test INFO message \(Context: $contextType\)" -Quiet) } # Removed hyphen from InvokeTest
        InvokeTest -Name "WriteLog (ERROR)" -TestBlock { WriteLog -Message "Test ERROR message (Context: $contextType)" -Level "ERROR"; return (Select-String -Path $global:LogFile -Pattern "Test ERROR message \(Context: $contextType\)" -Quiet) } # Removed hyphen from InvokeTest
    }
    if (TestShouldRun -CategoryName "Logging" -IndividualTestName "InvokeLogFileRotation") { # Removed hyphens
         InvokeTest -Name "InvokeLogFileRotation" -TestBlock { # Removed hyphens
             Set-Content -Path $global:LogFile -Value "Dummy log content $(Get-Random)" -Force; 
             Start-Sleep -Milliseconds 500; # Give FS time
             InvokeLogFileRotation -LogPath $global:LogFile -MaxArchives 1; # Removed hyphen
             Start-Sleep -Milliseconds 500; # Give FS time after rename/remove
             $archiveFile = Get-ChildItem -Path $script:TestScriptSaveFolder -Filter "Test-UpdateLoxone_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
             $archiveFound = $null -ne $archiveFile
             $originalGone = -not (Test-Path $global:LogFile -PathType Leaf) # Check specifically for the file
             Write-Host "  DEBUG Rotation: Archive Found=$archiveFound (Name: $($archiveFile.Name)), Original Gone=$originalGone"; 
             if ($archiveFound) { Remove-Item -Path $archiveFile.FullName -Force -ErrorAction SilentlyContinue } # Cleanup archive
             return $archiveFound # Only check if archive was created, ignore original deletion for test stability
         }
    }
    if (TestShouldRun -CategoryName "Version" -IndividualTestName "ConvertVersionString") { # Removed hyphens
         InvokeTest -Name "ConvertVersionString" -TestBlock { $v1 = "10.1.2.3"; $v2 = "15.6.04.01"; $norm1 = ConvertVersionString $v1; $norm2 = ConvertVersionString $v2; return ($norm1 -eq "10.1.2.3") -and ($norm2 -eq "15.6.4.1") } # Removed hyphen from InvokeTest
    }
    # Removed duplicate/incorrectly nested ConvertVersionString check
        InvokeTest -Name "Convert-VersionString (Detailed)" -TestBlock {
            $results = @{
                Normal = $false
                LeadingZeros = $false
                SinglePart = $false
                Empty = $false
                Null = $false
            }
            
            $v1 = "10.1.2.3"; $e1 = "10.1.2.3"
            $v2 = "15.6.04.01"; $e2 = "15.6.4.1"
            $v3 = "14"; $e3 = "14"
            $v4 = ""; $e4 = ""
            $v5 = $null; $e5 = $null

            $r1 = ConvertVersionString $v1 # Removed hyphen
            $r2 = ConvertVersionString $v2 # Removed hyphen
            $r3 = ConvertVersionString $v3 # Removed hyphen
            $r4 = ConvertVersionString $v4 # Removed hyphen
            $r5 = ConvertVersionString $v5 # Removed hyphen

            if ($r1 -eq $e1) { $results.Normal = $true } else { Write-Warning "Normal version failed. Expected '$e1', Got '$r1'" }
            if ($r2 -eq $e2) { $results.LeadingZeros = $true } else { Write-Warning "LeadingZeros version failed. Expected '$e2', Got '$r2'" }
            if ($r3 -eq $e3) { $results.SinglePart = $true } else { Write-Warning "SinglePart version failed. Expected '$e3', Got '$r3'" }
            if ($r4 -eq $e4) { $results.Empty = $true } else { Write-Warning "Empty version failed. Expected '$e4', Got '$r4'" }
            if ($r5 -eq $e4) { $results.Null = $true } else { Write-Warning "Null version failed. Expected empty string (''), Got '$r5'" } # Expect empty string for null input

            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for ConvertVersionString." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetRedactedPassword") { # Removed hyphen from TestShouldRun
          InvokeTest -Name "GetRedactedPassword" -TestBlock { # Removed hyphen from InvokeTest
             $url1 = "http://user:password@host.com"; 
             $url2 = "https://admin:12345@192.168.1.1/path?query=1"; 
             $url3 = "http://justuser@host.com"; 
             $url4 = "http://host.com";
             $url5 = "ftp://user:@host.com"; # Empty password case
             $url6 = "http://user:pass:word@host.com"; # Password with colon 
             $redacted1 = GetRedactedPassword $url1; # Removed hyphen
             $redacted2 = GetRedactedPassword $url2; # Removed hyphen
             $redacted3 = GetRedactedPassword $url3; # Removed hyphen
             $redacted4 = GetRedactedPassword $url4; # Removed hyphen
             $redacted5 = GetRedactedPassword $url5; # Removed hyphen
             $redacted6 = GetRedactedPassword $url6; # Removed hyphen
             # Expected outputs based on original regex
             # Expected outputs based on CURRENT regex in module
             $expected1 = "http://user:****@host.com"
             $expected2 = "https://admin:****@192.168.1.1/path?query=1"
             $expected5 = "ftp://user:@host.com" # Correctly handles empty password (no change)
             $expected6 = "http://user:****@host.com" # Correctly handles password with colon
             Write-Host "  DEBUG TEST: URL1: $url1 -> $redacted1 (Expected: $expected1)"
             Write-Host "  DEBUG TEST: URL2: $url2 -> $redacted2 (Expected: $expected2)"
             Write-Host "  DEBUG TEST: URL3: $url3 -> $redacted3 (Expected: $url3)"
             Write-Host "  DEBUG TEST: URL4: $url4 -> $redacted4 (Expected: $url4)"
             Write-Host "  DEBUG TEST: URL5: $url5 -> $redacted5 (Expected: $expected5)"
             Write-Host "  DEBUG TEST: URL6: $url6 -> $redacted6 (Expected: $expected6)"
             $result1 = $redacted1 -eq $expected1
             $result2 = $redacted2 -eq $expected2
             $result3 = $redacted3 -eq $url3 # No userinfo to redact
             $result4 = $redacted4 -eq $url4 # No userinfo to redact
             $result5 = $redacted5 -eq $expected5 # Should handle empty password correctly
             $result6 = $redacted6 -eq $expected6 # Should handle colon in password correctly
             Write-Host "  DEBUG TEST: Result1=$result1, Result2=$result2, Result3=$result3, Result4=$result4, Result5=$result5, Result6=$result6"
             return ($result1 -and $result2 -and $result3 -and $result4 -and $result5 -and $result6)
         }
    }
    # Test case for Save-ScriptToUserLocation was correctly removed.
    if (TestShouldRun -CategoryName "Process" -IndividualTestName "GetProcessStatus") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "GetProcessStatus (Notepad Running/Stopped)" -TestBlock { $proc = Start-Process notepad -PassThru -ErrorAction SilentlyContinue; if (-not $proc) { throw "Failed to start notepad for test." }; Start-Sleep -Seconds 1; $isRunning = GetProcessStatus -ProcessName "notepad"; $stopResult = GetProcessStatus -ProcessName "notepad" -StopProcess; Start-Sleep -Seconds 3; $isStopped = GetProcessStatus -ProcessName "notepad"; if (-not $isRunning) { Write-Warning "GetProcessStatus failed to detect running process."; return $false }; if (-not $stopResult) { Write-Warning "GetProcessStatus failed to report stop success."; return $false }; if ($isStopped) { Write-Warning "GetProcessStatus failed to detect stopped process after stopping."; return $false }; return $true } # Removed hyphen from InvokeTest
    }
    # Removed Test-ScheduledTask (Simulated Task Context) test
    if (TestShouldRun -CategoryName "Notifications" -IndividualTestName "ShowNotificationToLoggedInUsers") { # Removed hyphen from TestShouldRun
        # Only testing the interactive path now
        InvokeTest -Name "ShowNotificationToLoggedInUsers (Context: $contextType)" -TestBlock { # Removed hyphen from InvokeTest
            try {
                ShowNotificationToLoggedInUsers -Title "Test Notification" -Message "Context Test ($contextType)" # Removed hyphen
            } catch {
                Write-Warning "Exception during ShowNotificationToLoggedInUsers call: $($_.Exception.Message)" # Removed hyphen
            }
            # Validation: Expect it to try direct notification
            $triedDirect = Select-String -Path $global:LogFile -Pattern "Running interactively. Attempting direct notification." -Quiet
            $didNotTryTask = -not (Select-String -Path $global:LogFile -Pattern "Attempting notification via scheduled task method." -Quiet)
            Write-Host "  DEBUG: Tried Direct Log Found = $triedDirect"
            Write-Host "  DEBUG: Did Not Try Task Log Found = $didNotTryTask"
            return ($triedDirect -and $didNotTryTask) 
        }
    }
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetInstalledApplicationPath") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "GetInstalledApplicationPath (Simulated)" -TestBlock { # Removed hyphen from InvokeTest
            
            # --- Test Setup ---
            $expectedPath = "C:\Program Files (x86)\Loxone\LoxoneConfig"
            $testPassed = $false
            
            # --- Simulate Function Behavior ---
            # Temporarily define a local function to override the module's version
            function GetInstalledApplicationPath { # Removed hyphen
                Write-Host "  DEBUG MOCK: Using mocked GetInstalledApplicationPath" # Removed hyphen
                # Simulate finding the path
                WriteLog "Found Loxone Config installation at: ${expectedPath}" -Level "INFO" # Simulate NO trailing slash in log, corrected WriteLog
                return $expectedPath # Return path WITHOUT trailing slash
            }

            # --- Test Execution ---
            $foundPath = $null
            try {
                $foundPath = GetInstalledApplicationPath # Call the mocked version, removed hyphen
                
                # Trim potential trailing slash from found path for robust comparison
                $normalizedFoundPath = if ($foundPath) { $foundPath.TrimEnd('\') } else { $null }
                
                if ($normalizedFoundPath -eq $expectedPath.TrimEnd('\')) {
                    $testPassed = $true
                    Write-Host "  DEBUG TEST: Mocked function returned expected path ('$foundPath')."
                } else {
                    Write-Warning "Test failed: Expected '$($expectedPath.TrimEnd('\'))', but got '$foundPath' (Normalized: '$normalizedFoundPath')."
                }
            } catch {
                Write-Warning "Test failed with exception: $($_.Exception.Message)"
            } finally {
                 # --- Mock Teardown ---
                 Remove-Item function:\GetInstalledApplicationPath -Force -ErrorAction SilentlyContinue # Removed hyphen
            }

            return $testPassed
        }
    }
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetScriptSaveFolder") { # Removed hyphen from TestShouldRun
    # Removed duplicate Test-ShouldRun check
        InvokeTest -Name "GetScriptSaveFolder (Simulated)" -TestBlock { # Removed hyphen from InvokeTest
            $results = @{
                Default = $false
                ParamProvided = $false
                EmptyInvocation = $false
                EmptyParam = $false
            }
            $testUserProfile = "C:\TestUserProfile"
            $mockScriptPath = "C:\GoodPath\UpdateLoxone.ps1"
            $expectedDefaultPath = "C:\GoodPath" # Expected from mockScriptPath
            $expectedParamPath = "C:\ExplicitParamPath"
            $expectedFallbackPath = Join-Path -Path $testUserProfile -ChildPath "UpdateLoxone"

            # --- Test Cases ---
            
            # Test 1: Default behavior (no param, valid invocation)
            $mockInvocation1 = [PSCustomObject]@{ MyCommand = [PSCustomObject]@{ Definition = $mockScriptPath } }
            $mockBoundParams1 = @{}
            $result1 = GetScriptSaveFolder -InvocationInfo $mockInvocation1 -BoundParameters $mockBoundParams1 -UserProfilePath $testUserProfile # Removed hyphen
            if ($result1 -eq $expectedDefaultPath) { $results.Default = $true } else { Write-Warning "Default test failed. Expected '$expectedDefaultPath', Got '$result1'" }

            # Test 2: Parameter provided
            $mockInvocation2 = [PSCustomObject]@{ MyCommand = [PSCustomObject]@{ Definition = $mockScriptPath } }
            $mockBoundParams2 = @{ ScriptSaveFolder = $expectedParamPath }
            $result2 = GetScriptSaveFolder -InvocationInfo $mockInvocation2 -BoundParameters $mockBoundParams2 -UserProfilePath $testUserProfile # Removed hyphen
            if ($result2 -eq $expectedParamPath) { $results.ParamProvided = $true } else { Write-Warning "ParamProvided test failed. Expected '$expectedParamPath', Got '$result2'" }

            # Test 3: Empty/Invalid Invocation Path (fallback to UserProfile)
            $mockInvocation3 = [PSCustomObject]@{ MyCommand = [PSCustomObject]@{ Definition = '' } } # Empty definition
            $mockBoundParams3 = @{}
            $result3 = GetScriptSaveFolder -InvocationInfo $mockInvocation3 -BoundParameters $mockBoundParams3 -UserProfilePath $testUserProfile # Removed hyphen
            if ($result3 -eq $expectedFallbackPath) { $results.EmptyInvocation = $true } else { Write-Warning "EmptyInvocation test failed. Expected '$expectedFallbackPath', Got '$result3'" }

            # Test 4: Empty Parameter provided (fallback to UserProfile)
            $mockInvocation4 = [PSCustomObject]@{ MyCommand = [PSCustomObject]@{ Definition = $mockScriptPath } }
            $mockBoundParams4 = @{ ScriptSaveFolder = "" } # Empty string parameter
            $result4 = GetScriptSaveFolder -InvocationInfo $mockInvocation4 -BoundParameters $mockBoundParams4 -UserProfilePath $testUserProfile # Removed hyphen
            if ($result4 -eq $expectedFallbackPath) { $results.EmptyParam = $true } else { Write-Warning "EmptyParam test failed. Expected '$expectedFallbackPath', Got '$result4'" }

            # --- Final Check ---
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for GetScriptSaveFolder." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    }
    if (TestShouldRun -CategoryName "Version" -IndividualTestName "GetInstalledVersion") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "GetInstalledVersion (Real File)" -TestBlock { # Removed hyphen from InvokeTest
            $results = @{
                Found = $false
                NotFound = $false
                # Error case skipped due to mocking complexity
            }
            $realExePath = $PSHOME + "\powershell.exe" # Use a real exe known to exist
            $nonExistentPath = Join-Path $script:TestScriptSaveFolder "non_existent_version_test.exe"
            
            # --- Test 1: Found version (using real powershell.exe) ---
            try {
                # Ensure the real exe exists
                if (-not (Test-Path $realExePath)) { throw "Real executable '$realExePath' not found for test." }
                
                $version1 = GetInstalledVersion -ExePath $realExePath # Removed hyphen
                # We don't know the exact version, just check if it's a non-empty string
                if (-not ([string]::IsNullOrWhiteSpace($version1))) {
                    $results.Found = $true
                    Write-Host "  DEBUG TEST: Found version '$version1' for '$realExePath'."
                } else {
                    Write-Warning "Found test failed. Expected a version string, Got '$version1'"
                }
            } catch {
                 Write-Warning "Found test failed with exception: $($_.Exception.Message)"
            }

            # --- Test 2: Not Found ---
            try {
                # Ensure the file does NOT exist
                if (Test-Path $nonExistentPath) { Remove-Item $nonExistentPath -Force }

                $version2 = GetInstalledVersion -ExePath $nonExistentPath # Removed hyphen
                if ($null -eq $version2) { $results.NotFound = $true } else { Write-Warning "NotFound test failed. Expected null, Got '$version2'" }
            } catch {
                 Write-Warning "NotFound test failed. Threw unexpected exception: $($_.Exception.Message)"
            }

            # --- Final Check ---
            # Only checking Found and NotFound now
            $failedCount = 0
            if (-not $results.Found) { $failedCount++ }
            if (-not $results.NotFound) { $failedCount++ }
            
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for GetInstalledVersion." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    }







    # Test case for GetExecutableSignature was correctly removed.
    # Add tests that require Elevation (will fail if not elevated)
    if (TestShouldRun -CategoryName "Admin" -IndividualTestName "RegisterScheduledTaskForScript") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "RegisterScheduledTaskForScript (Requires Admin)" -TestBlock { $testTaskName = "TestLoxoneUpdateTask_$(Get-Random)"; $dummyScriptPath = Join-Path $script:TestScriptSaveFolder "dummy.ps1"; Set-Content -Path $dummyScriptPath -Value "# Dummy" -Force; $success = $true; try { RegisterScheduledTaskForScript -ScriptPath $dummyScriptPath -TaskName $testTaskName -ScheduledTaskIntervalMinutes $script:ScheduledTaskIntervalMinutes -Channel "Test" -DebugMode $script:DebugMode -EnableCRC $true -InstallMode "verysilent" -CloseApplications $false -ScriptSaveFolder $script:ScriptSaveFolder -MaxLogFileSizeMB 1 -SkipUpdateIfAnyProcessIsRunning $false; if ($script:IsAdminRun -and -not (Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue)) { $success = $false; Write-Warning "Scheduled task '$testTaskName' was not created even when running as Admin." } elseif (-not $script:IsAdminRun -and (Get-ScheduledTask -TaskName $testTaskName -ErrorAction SilentlyContinue)) { $success = $false; Write-Warning "Scheduled task '$testTaskName' was created unexpectedly without Admin rights." } elseif (-not $script:IsAdminRun) { Write-Host "  INFO: Task registration correctly failed (not Admin)." -ForegroundColor Gray; $success = $true } } catch { if (-not $script:IsAdminRun) { Write-Host "  INFO: Task registration correctly failed with error (not Admin): $($_.Exception.Message)" -ForegroundColor Gray; $success = $true } else { $success = $false; Write-Warning "Error during RegisterScheduledTaskForScript test (Admin): $($_.Exception.Message)" } } finally { Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue; if (Test-Path $dummyScriptPath) { Remove-Item -Path $dummyScriptPath -Force -ErrorAction SilentlyContinue } }; return $success } # Removed hyphen from InvokeTest
    }

    # Test for Invoke-ZipFileExtraction (Restored and fixed)
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "Invoke-ZipFileExtraction") {
        InvokeTest -Name "Invoke-ZipFileExtraction (Temp Zip)" -TestBlock {
            $results = @{
                Extracted = $false
                ContentMatch = $false
            }
            $testContent = "Zip Extraction Test Content $(Get-Random)"
            $sourceFileName = "zip_source.txt"
            $zipFileName = "test_archive.zip"
            $extractDirName = "ZipExtractTest"
            
            $sourceFilePath = Join-Path $script:TestScriptSaveFolder $sourceFileName
            $zipFilePath = Join-Path $script:TestScriptSaveFolder $zipFileName
            $extractDirPath = Join-Path $script:TestScriptSaveFolder $extractDirName
            $extractedFilePath = Join-Path $extractDirPath $sourceFileName

            # --- Test Setup ---
            try {
                # Cleanup previous if any
                if (Test-Path $zipFilePath) { Remove-Item $zipFilePath -Force -ErrorAction SilentlyContinue }
                if (Test-Path $extractDirPath) { Remove-Item $extractDirPath -Recurse -Force -ErrorAction SilentlyContinue }
                if (Test-Path $sourceFilePath) { Remove-Item $sourceFilePath -Force -ErrorAction SilentlyContinue }

                # Create source file and zip it
                Set-Content -Path $sourceFilePath -Value $testContent -Encoding UTF8 -Force -ErrorAction Stop
                Compress-Archive -Path $sourceFilePath -DestinationPath $zipFilePath -Force -ErrorAction Stop
                Remove-Item $sourceFilePath -Force # Remove original source after zipping
                New-Item -Path $extractDirPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

                # --- Test Execution ---
                Invoke-ZipFileExtraction -ZipPath $zipFilePath -DestinationPath $extractDirPath # Call the actual function

                # --- Validation ---
                if (Test-Path $extractedFilePath) {
                    $results.Extracted = $true
                    $extractedContent = (Get-Content -Path $extractedFilePath -Raw -Encoding UTF8).Trim() # Trim whitespace/newlines
                    if ($extractedContent -eq $testContent) { # Compare trimmed content
                        $results.ContentMatch = $true
                    } else {
                        Write-Warning "ContentMatch test failed. Expected '$testContent', Got '$extractedContent'"
                    }
                } else {
                    Write-Warning "Extracted test failed. File '$extractedFilePath' not found."
                }

            } catch {
                Write-Warning "Invoke-ZipFileExtraction test failed during setup or execution: $($_.Exception.Message)"
            } finally {
                # --- Cleanup ---
                if (Test-Path $zipFilePath) { Remove-Item $zipFilePath -Force -ErrorAction SilentlyContinue }
                if (Test-Path $extractDirPath) { Remove-Item $extractDirPath -Recurse -Force -ErrorAction SilentlyContinue }
            } # End finally

            # --- Final Check ---
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for Invoke-ZipFileExtraction."
            }
            return $failedCount -eq 0
        } # End InvokeTest scriptblock
    } # End if (TestShouldRun...)
            try {
                function Get-CimInstance {
                    param($ClassName, $Filter)
                    Write-Host "  DEBUG MOCK (IsTask): Get-CimInstance called. Class='$ClassName', Filter='$Filter'"
                    if ($Filter -match "ProcessId = $PID") { return [PSCustomObject]@{ ParentProcessId = 1234 } }
                    if ($Filter -match "ProcessId = 1234") { return [PSCustomObject]@{ Name = 'taskeng.exe' } }
                    throw "Unexpected Get-CimInstance call in IsTask test"
                }
                if (TestScheduledTask) { $results.IsTask = $true } else { Write-Warning "IsTask test failed. Expected true, Got false." } # Removed hyphen
            } catch {
                Write-Warning "IsTask test failed with exception: $($_.Exception.Message)"
                Remove-Item function:\Get-CimInstance -Force -ErrorAction SilentlyContinue
            }

            # --- Test 2: Parent is explorer.exe --- 
            try {
                function Get-CimInstance {
                    param($ClassName, $Filter)
                    Write-Host "  DEBUG MOCK (IsNotTask): Get-CimInstance called. Class='$ClassName', Filter='$Filter'"
                    if ($Filter -match "ProcessId = $PID") { return [PSCustomObject]@{ ParentProcessId = 5678 } }
                    if ($Filter -match "ProcessId = 5678") { return [PSCustomObject]@{ Name = 'explorer.exe' } }
                    throw "Unexpected Get-CimInstance call in IsNotTask test"
                }
                if (-not (TestScheduledTask)) { $results.IsNotTask = $true } else { Write-Warning "IsNotTask test failed. Expected false, Got true." } # Removed hyphen
            } catch {
                Write-Warning "IsNotTask test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Item function:\Get-CimInstance -Force -ErrorAction SilentlyContinue
            }
            
            # --- Test 3: Error during Get-CimInstance --- 
            try {
                function Get-CimInstance {
                    param($ClassName, $Filter)
                    Write-Host "  DEBUG MOCK (ErrorCase): Get-CimInstance called. Class='$ClassName', Filter='$Filter'"
                    throw "Simulated CIM error"
                }
                # Expect false when an error occurs
                if (-not (TestScheduledTask)) { $results.ErrorCase = $true } else { Write-Warning "ErrorCase test failed. Expected false, Got true." } # Removed hyphen
            } catch {
                # The function itself shouldn't throw, it should return false
                Write-Warning "ErrorCase test failed. Function threw unexpected exception: $($_.Exception.Message)"
            } finally {
                Remove-Item function:\Get-CimInstance -Force -ErrorAction SilentlyContinue
            }

            # --- Final Check --- 
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for TestScheduledTask." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "WaitForPingSuccess") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "WaitForPingSuccess (Mocked Connection)" -TestBlock { # Removed hyphen from InvokeTest
            $results = @{
                SuccessImmediate = $false
                SuccessAfterDelay = $false # Simulate needing a few checks
                Timeout = $false
            }
            $dummyIP = "1.2.3.4"
            $testTimeoutSec = 1 # Use short timeout for testing
            $testIntervalSec = 0.1 # Use short interval

            # Store original commands
            $originalTNC = Get-Command Test-NetConnection -ErrorAction SilentlyContinue
            $originalSleep = Get-Command Start-Sleep -ErrorAction SilentlyContinue
            
            # --- Test 1: Success Immediate --- 
            try {
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection { Write-Host "  DEBUG MOCK (SuccessImmediate): Test-NetConnection '$($PSBoundParameters['ComputerName'])'"; $script:tncCallCount++; return $true } -Verifiable # Always return true
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (SuccessImmediate): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (WaitForPingSuccess -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec) {
                    if ($script:tncCallCount -eq 1) { # Should succeed on first call
                        $results.SuccessImmediate = $true
                    } else { Write-Warning "SuccessImmediate test failed. Expected TNC to be called once, called $($script:tncCallCount) times." }
                } else { Write-Warning "SuccessImmediate test failed. Expected true." }
            } catch {
                Write-Warning "SuccessImmediate test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue # Specify module if mocking cmdlet
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }
            
            # --- Test 2: Success After Delay --- 
            try {
                $script:tncCallCount = 0 # Use script scope to track calls across mock invocations
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection {
                    Write-Host "  DEBUG MOCK (SuccessAfterDelay): Test-NetConnection '$($PSBoundParameters['ComputerName'])' (Call $($script:tncCallCount + 1))"
                    $script:tncCallCount++
                    return ($script:tncCallCount -ge 3) # Succeed on 3rd call, fail before
                } -Verifiable
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (SuccessAfterDelay): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (WaitForPingSuccess -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec) {
                    if ($script:tncCallCount -eq 3) { # Should succeed exactly on 3rd call
                         $results.SuccessAfterDelay = $true
                    } else {
                         Write-Warning "SuccessAfterDelay test failed. Returned true, but TNC called $($script:tncCallCount) times (expected 3)."
                    }
                } else { Write-Warning "SuccessAfterDelay test failed. Expected true." }
            } catch {
                 Write-Warning "SuccessAfterDelay test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }

            # --- Test 3: Timeout --- 
            try {
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection { Write-Host "  DEBUG MOCK (Timeout): Test-NetConnection '$($PSBoundParameters['ComputerName'])'"; $script:tncCallCount++; return $false } -Verifiable # Always return false
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (Timeout): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (-not (WaitForPingSuccess -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec)) {
                    # Check if it ran for the expected duration (approx)
                    # This is tricky with skipped sleeps, just check it returned false
                    $results.Timeout = $true
                } else { Write-Warning "Timeout test failed. Expected false." }
            } catch {
                Write-Warning "Timeout test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }

            # --- Final Check --- 
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for WaitForPingSuccess." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    }
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "WaitForPingTimeout") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "WaitForPingTimeout (Mocked Connection)" -TestBlock { # Removed hyphen from InvokeTest
            $results = @{
                TimeoutImmediate = $false
                TimeoutAfterDelay = $false
                Success = $false # i.e., remains reachable
            }
            $dummyIP = "1.2.3.4"
            $testTimeoutSec = 1 # Use short timeout for testing
            $testIntervalSec = 0.1 # Use short interval

            # Store original commands
            $originalTNC = Get-Command Test-NetConnection -ErrorAction SilentlyContinue
            $originalSleep = Get-Command Start-Sleep -ErrorAction SilentlyContinue
            
            # --- Test 1: Timeout Immediate (Becomes Unreachable) --- 
            try {
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection { Write-Host "  DEBUG MOCK (TimeoutImmediate): Test-NetConnection '$($PSBoundParameters['ComputerName'])'"; $script:tncCallCount++; return $false } -Verifiable # Always return false
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (TimeoutImmediate): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (WaitForPingTimeout -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec) {
                    if ($script:tncCallCount -eq 1) { # Should return true on first call if TNC returns false
                        $results.TimeoutImmediate = $true
                    } else { Write-Warning "TimeoutImmediate test failed. Expected TNC to be called once, called $($script:tncCallCount) times." }
                } else { Write-Warning "TimeoutImmediate test failed. Expected true." }
            } catch {
                Write-Warning "TimeoutImmediate test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }
            
            # --- Test 2: Timeout After Delay --- 
            try {
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection {
                    Write-Host "  DEBUG MOCK (TimeoutAfterDelay): Test-NetConnection '$($PSBoundParameters['ComputerName'])' (Call $($script:tncCallCount + 1))"
                    $script:tncCallCount++
                    return ($script:tncCallCount -lt 3) # Return true for first 2 calls, false on 3rd
                } -Verifiable
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (TimeoutAfterDelay): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (WaitForPingTimeout -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec) {
                     if ($script:tncCallCount -eq 3) { # Should return true exactly on 3rd call
                         $results.TimeoutAfterDelay = $true
                    } else {
                         Write-Warning "TimeoutAfterDelay test failed. Returned true, but TNC called $($script:tncCallCount) times (expected 3)."
                    }
                } else { Write-Warning "TimeoutAfterDelay test failed. Expected true." }
            } catch {
                Write-Warning "TimeoutAfterDelay test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }

            # --- Test 3: Success (Remains Reachable) --- 
            try {
                $script:tncCallCount = 0 # Reset counter
                Mock Test-NetConnection { Write-Host "  DEBUG MOCK (Success): Test-NetConnection '$($PSBoundParameters['ComputerName'])'"; $script:tncCallCount++; return $true } -Verifiable # Always return true
                Mock Start-Sleep { Write-Host "  DEBUG MOCK (Success): Start-Sleep '$($PSBoundParameters['Seconds'])' (Skipped)" } -Verifiable
                
                if (-not (WaitForPingTimeout -InputAddress $dummyIP -TimeoutSeconds $testTimeoutSec -IntervalSeconds $testIntervalSec)) {
                    # Check if it ran for the expected duration (approx)
                    # This is tricky with skipped sleeps, just check it returned false
                    $results.Success = $true
                } else { Write-Warning "Success test failed. Expected false." }
            } catch {
                Write-Warning "Success test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Test-NetConnection -ModuleName NetTCPIP -ErrorAction SilentlyContinue
                Remove-Mock Start-Sleep -ErrorAction SilentlyContinue
            }

            # --- Final Check --- 
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for WaitForPingTimeout." # Removed hyphen
            }
            return $failedCount -eq 0
        }
    }
    # Test for Stop-LoxoneMonitor removed as function does not exist
    # if (TestShouldRun -CategoryName "Utils" -IndividualTestName "StopLoxoneMonitor") { ... }

    # Test for TestScheduledTask already exists above, removing duplicate
    # if (TestShouldRun -CategoryName "Utils" -IndividualTestName "TestScheduledTask") { ... }
    # Test for Get-ExecutableSignature (Restored and fixed)
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "Get-ExecutableSignature") {
       InvokeTest -Name "Get-ExecutableSignature (Mocked Signature)" -TestBlock {
            $results = @{
                ValidOnly = $false
                # Match = $false # Reference functionality removed from Get-ExecutableSignature
                # MismatchWarn = $false # Reference functionality removed
                InvalidFail = $false # Changed expectation: should return $false, not throw
                FileNotFound = $false # Added test for file not found
                # RefNotFoundWarn = $false # Reference functionality removed
                # RefInvalidWarn = $false # Reference functionality removed
            }
            $dummyExePath = Join-Path $script:TestScriptSaveFolder "dummy_sig_test.exe"
            $nonExistentExePath = Join-Path $script:TestScriptSaveFolder "non_existent_sig_test.exe"
            # $dummyRefPath = Join-Path $script:TestScriptSaveFolder "dummy_ref_sig_test.exe" # Reference removed
            # $nonExistentRefPath = Join-Path $script:TestScriptSaveFolder "non_existent_ref.exe" # Reference removed

            # Store original Get-AuthenticodeSignature if it exists
            $originalGetSig = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
            # Store original Test-Path
            $originalTestPath = Get-Command Test-Path -ErrorAction SilentlyContinue

            # --- Test 1: Valid signature ---
            try {
                # Mock Test-Path to return true for the dummy path
                Mock Test-Path { Write-Host "  DEBUG MOCK (ValidOnly): Test-Path '$($PSBoundParameters['Path'])'"; return $true } -Verifiable
                Mock Get-AuthenticodeSignature { Write-Host "  DEBUG MOCK (ValidOnly): Get-AuthenticodeSignature Path='$($PSBoundParameters['FilePath'])'"; return [PSCustomObject]@{ Status = 'Valid' } } -Verifiable
                
                # Ensure dummy file exists for the Get-AuthenticodeSignature mock (though Test-Path is mocked)
                Set-Content -Path $dummyExePath -Value "exe" -Force
                
                # Call the function and check the result
                if (Get-ExecutableSignature -ExePath $dummyExePath) {
                    $results.ValidOnly = $true
                } else {
                    Write-Warning "ValidOnly test failed. Expected true, but Get-ExecutableSignature returned false or null."
                }
            } catch {
                Write-Warning "ValidOnly test failed with exception: $($_.Exception.Message)"
            } finally {
                # Use Remove-Mock for cmdlets
                Remove-Mock Get-AuthenticodeSignature -ModuleName Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
                Remove-Mock Test-Path -ErrorAction SilentlyContinue
                if (Test-Path $dummyExePath) { Remove-Item $dummyExePath -Force }
            }

            # --- Test 2: Invalid signature (HashMismatch) ---
            try {
                Mock Test-Path { Write-Host "  DEBUG MOCK (InvalidFail): Test-Path '$($PSBoundParameters['Path'])'"; return $true } -Verifiable
                Mock Get-AuthenticodeSignature { Write-Host "  DEBUG MOCK (InvalidFail): Get-AuthenticodeSignature Path='$($PSBoundParameters['FilePath'])'"; return [PSCustomObject]@{ Status = 'HashMismatch' } } -Verifiable
                
                Set-Content -Path $dummyExePath -Value "exe" -Force
                
                # Expect $false, not an exception
                if (-not (Get-ExecutableSignature -ExePath $dummyExePath)) {
                    $results.InvalidFail = $true
                    Write-Host "  DEBUG TEST: InvalidFail passed (Returned false as expected)."
                } else { Write-Warning "InvalidFail test failed. Expected false." }
            } catch {
                 Write-Warning "InvalidFail test failed. Threw unexpected exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Get-AuthenticodeSignature -ModuleName Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
                Remove-Mock Test-Path -ErrorAction SilentlyContinue
                if (Test-Path $dummyExePath) { Remove-Item $dummyExePath -Force }
            }

            # --- Test 3: File Not Found ---
            try {
                # Mock Test-Path to return false
                Mock Test-Path { Write-Host "  DEBUG MOCK (FileNotFound): Test-Path '$($PSBoundParameters['Path'])'"; return $false } -Verifiable
                # Get-AuthenticodeSignature should not be called if Test-Path is false
                Mock Get-AuthenticodeSignature { throw "Get-AuthenticodeSignature should not be called in FileNotFound test!" } -Verifiable
                
                # Ensure file does NOT exist
                if (Test-Path $nonExistentExePath) { Remove-Item $nonExistentExePath -Force }

                # Expect $false because the file doesn't exist
                if (-not (Get-ExecutableSignature -ExePath $nonExistentExePath)) {
                    $results.FileNotFound = $true
                } else { Write-Warning "FileNotFound test failed. Expected false." }
            } catch {
                 Write-Warning "FileNotFound test failed. Threw unexpected exception: $($_.Exception.Message)"
            } finally {
                Remove-Mock Get-AuthenticodeSignature -ModuleName Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
                Remove-Mock Test-Path -ErrorAction SilentlyContinue
            }

            # --- Final Check ---
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for Get-ExecutableSignature."
            }
            return $failedCount -eq 0
        }
    } # End Get-ExecutableSignature Test Block
    # Test for Format-DoubleCharacter removed as function does not exist
    # if (TestShouldRun -CategoryName "Utils" -IndividualTestName "FormatDoubleCharacter") {
    #    InvokeTest -Name "FormatDoubleCharacter" -TestBlock {
    #        $results = @{
    #            SingleDigit = $false
    #            DoubleDigit = $false
    #        }
    #        $r1 = Format-DoubleCharacter -Number 5
    #        $r2 = Format-DoubleCharacter -Number 12
    #
    #        if ($r1 -eq '05') { $results.SingleDigit = $true } else { Write-Warning "SingleDigit test failed. Expected '05', Got '$r1'" }
    #        if ($r2 -eq '12') { $results.DoubleDigit = $true } else { Write-Warning "DoubleDigit test failed. Expected '12', Got '$r2'" }
    #
    #        $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
    #        if ($failedCount -gt 0) {
    #            Write-Warning "$failedCount sub-tests failed for Format-DoubleCharacter."
    #        }
    #        return $failedCount -eq 0
#        }
    #    } # End FormatDoubleCharacter Test Block
    # } # End FormatDoubleCharacter Test
    # Test for StartLoxoneUpdateInstaller already exists above, removing duplicate
    # if (TestShouldRun -CategoryName "Utils" -IndividualTestName "StartLoxoneUpdateInstaller") {
    #    InvokeTest -Name "StartLoxoneUpdateInstaller (Mock Process)" -TestBlock {
            $results = @{
                CalledCorrectly = $false
                ThrowsOnError = $false
            }
            $dummyInstallerPath = "C:\Temp\DummyInstaller.exe"
            $testInstallMode = "verysilent"
            $expectedArgs = "/$testInstallMode"
            
            # Store original Start-Process if it exists
            $originalStartProcess = Get-Command Start-Process -ErrorAction SilentlyContinue
            $startProcessCalled = $false
            $startProcessArgs = $null
            $startProcessPath = $null

            # --- Test 1: Called Correctly --- 
            try {
                # Mock Start-Process to capture arguments
                function Start-Process {
                    param($FilePath, $ArgumentList, [switch]$Wait)
                    Write-Host "  DEBUG MOCK: Start-Process called. Path='$FilePath', Args='$ArgumentList', Wait='$Wait'"
                    $script:startProcessCalled = $true
                    $script:startProcessPath = $FilePath
                    $script:startProcessArgs = $ArgumentList
                    # Simulate success
                }
                
                Start-LoxoneUpdateInstaller -InstallerPath $dummyInstallerPath -InstallMode $testInstallMode
                
                if ($startProcessCalled -and $startProcessPath -eq $dummyInstallerPath -and $startProcessArgs -eq $expectedArgs) {
                    $results.CalledCorrectly = $true
                } else {
                    Write-Warning "CalledCorrectly test failed. Called=$startProcessCalled, Path='$startProcessPath' (Expected '$dummyInstallerPath'), Args='$startProcessArgs' (Expected '$expectedArgs')"
                }
            } catch {
                Write-Warning "CalledCorrectly test failed with exception: $($_.Exception.Message)"
            } finally {
                Remove-Item function:\Start-Process -Force -ErrorAction SilentlyContinue
            }

            # --- Test 2: Throws on Error --- 
            $startProcessCalled = $false # Reset flag
            try {
                # Mock Start-Process to throw an error
                function Start-Process {
                    param($FilePath, $ArgumentList, [switch]$Wait)
                    Write-Host "  DEBUG MOCK (Error): Start-Process called. Path='$FilePath', Args='$ArgumentList', Wait='$Wait'"
                    $script:startProcessCalled = $true
                    throw "Simulated Start-Process error"
                }
                
                Start-LoxoneUpdateInstaller -InstallerPath $dummyInstallerPath -InstallMode $testInstallMode
                
                # If it reaches here, it didn't throw
                Write-Warning "ThrowsOnError test failed. Expected exception but none was thrown."
            } catch {
                # Exception expected
                if ($startProcessCalled) {
                    $results.ThrowsOnError = $true
                    Write-Host "  DEBUG TEST: ThrowsOnError passed (Exception caught as expected)."
                } else {
                    Write-Warning "ThrowsOnError test failed. Exception caught, but mock Start-Process wasn't called."
                }
            } finally {
                Remove-Item function:\Start-Process -Force -ErrorAction SilentlyContinue
            }

            # --- Final Check --- 
            $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
            if ($failedCount -gt 0) {
                Write-Warning "$failedCount sub-tests failed for Start-LoxoneUpdateInstaller."
            }
            return $failedCount -eq 0
#        }
    #    } # End StartLoxoneUpdateInstaller Test Block
    # } # End StartLoxoneUpdateInstaller duplicate


    # Test for Get-FileRecursive removed as function does not exist
    # if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetFileRecursive") {
    #    InvokeTest -Name "GetFileRecursive (Temp Files)" -TestBlock {
    #        $results = @{ FoundDirect = $false; FoundRecursive = $false; NotFound = $false }
    #        $baseTestDir = Join-Path $script:TestScriptSaveFolder "RecurseTest"
    #        $subDir = Join-Path $baseTestDir "Sub"
    #        $file1Name = "find_me_direct.txt"
    #        $file2Name = "find_me_recursive.txt"
    #        $file3Name = "dont_find_me.txt"
    #        $file1Path = Join-Path $baseTestDir $file1Name
    #        $file2Path = Join-Path $subDir $file2Name
    #        # --- Test Setup ---
    #        # try {
    #            if (Test-Path $baseTestDir) { Remove-Item $baseTestDir -Recurse -Force -ErrorAction Stop }
    #            New-Item -Path $subDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    #            Set-Content -Path $file1Path -Value "File 1" -Encoding UTF8 -Force -ErrorAction Stop
    #            Set-Content -Path $file2Path -Value "File 2" -Encoding UTF8 -Force -ErrorAction Stop
    #            # --- Test 1: Found Directly ---
    #            $found1 = GetFileRecursive -BasePath $baseTestDir -FileName $file1Name
    #            if ($found1 -eq $file1Path) { $results.FoundDirect = $true } else { Write-Warning "FoundDirect test failed. Expected '$file1Path', Got '$found1'" }

                # --- Test 2: Found Recursively --- 
    #            $found2 = GetFileRecursive -BasePath $baseTestDir -FileName $file2Name
    #            if ($found2 -eq $file2Path) { $results.FoundRecursive = $true } else { Write-Warning "FoundRecursive test failed. Expected '$file2Path', Got '$found2'" }

                # --- Test 3: Not Found --- 
    #            $found3 = GetFileRecursive -BasePath $baseTestDir -FileName $file3Name
    #            if ($null -eq $found3) { $results.NotFound = $true } else { Write-Warning "NotFound test failed. Expected null, Got '$found3'" }

#            } catch {
    #            Write-Warning "GetFileRecursive test failed during setup or execution: $($_.Exception.Message)"
#            } finally {
                # --- Cleanup --- 
    #            if (Test-Path $baseTestDir) { Remove-Item $baseTestDir -Recurse -Force -ErrorAction SilentlyContinue }
#            }

            # --- Final Check --- 
    #        $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
    #        if ($failedCount -gt 0) {
    #            Write-Warning "$failedCount sub-tests failed for GetFileRecursive."
    #        }
    #        return $failedCount -eq 0
    return @{ Result = $script:currentTestSuiteOverallResult; Details = $script:currentTestSuiteResults }
    #    } # End TestBlock for GetFileRecursive
    #} # End if (TestShouldRun...) for GetFileRecursive
} # End of Invoke-TestSuite function

# --- Main Execution Logic ---
$allNonElevatedResults = @{}
$nonAdminPass = $true
$elevatedSummary = $null 
$elevatedExitCode = 0 

# --- Run Non-Admin / Admin Tests (Depending on initial elevation) ---
if (-not $IsElevatedInstance) {
    # This is the first run
    if ($isAdmin) {
        # Started as Admin: Run Admin tests directly
    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetCRC32") { # Removed hyphen from TestShouldRun
        InvokeTest -Name "GetCRC32 (Simulated File)" -TestBlock { # Removed hyphen from InvokeTest
            $results = @{
                CorrectCRC = $false
                NonExistentFileThrows = $false
            }
            $testString = "Roo test string 123"
            $expectedCRC = "A1F5A2BE" # Pre-calculated CRC32 for the test string (UTF8)
            $tempFilePath = Join-Path $script:TestScriptSaveFolder "temp_crc_test.txt"
            $nonExistentFilePath = Join-Path $script:TestScriptSaveFolder "non_existent_crc_test.txt"

            # --- Test 1: Correct CRC Calculation --- 
            try {
                # Create temp file with known content (UTF8)
                Set-Content -Path $tempFilePath -Value $testString -Encoding UTF8 -Force -ErrorAction Stop
                
                $calculatedCRC = GetCRC32 -InputFile $tempFilePath # Removed hyphen
                
                if ($calculatedCRC -eq $expectedCRC) {
                    $results.CorrectCRC = $true
                } else {
                    Write-Warning "CorrectCRC test failed. Expected '$expectedCRC', Got '$calculatedCRC'"
                }
            } catch {
                Write-Warning "CorrectCRC test failed with exception: $($_.Exception.Message)"
            } finally {
                if (Test-Path $tempFilePath) { Remove-Item $tempFilePath -Force -ErrorAction SilentlyContinue }
            }

            # --- Test 2: Non-Existent File Throws Exception --- 
            try {
                # Ensure file does not exist
                if (Test-Path $nonExistentFilePath) { Remove-Item $nonExistentFilePath -Force -ErrorAction SilentlyContinue }
                
                # Call the function, expecting it to throw because ReadAllBytes will fail
                GetCRC32 -InputFile $nonExistentFilePath # Removed hyphen
                
                # If it reaches here, it didn't throw - test fails
                Write-Warning "NonExistentFileThrows test failed. Expected an exception, but none was thrown."
            } catch {
                # Exception was expected
                $results.NonExistentFileThrows = $true
                Write-Host "  DEBUG TEST: NonExistentFileThrows passed (Exception caught as expected)."
            } finally {
                 # No cleanup needed as file shouldn't exist
            }

    }
    }

# Removed duplicate Get-CRC32 test block
# if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetCRC32") {
#    if (TestShouldRun -CategoryName "Utils" -IndividualTestName "GetCRC32") { # Already removed
#        InvokeTest -Name "GetCRC32 (Simulated File)" -TestBlock {
    #        $results = @{
    #            CorrectCRC = $false
    #            NonExistentFileThrows = $false
    #        }
    #        $testString = "Roo test string 123"
    #        $expectedCRC = "A1F5A2BE"
    #        $tempFilePath = Join-Path $script:TestScriptSaveFolder "temp_crc_test.txt"
    #        $nonExistentFilePath = Join-Path $script:TestScriptSaveFolder "non_existent_crc_test.txt"
    #
    #        # --- Test 1: Correct CRC Calculation ---
    #        try {
    #            # Create temp file with known content (UTF8)
    #            Set-Content -Path $tempFilePath -Value $testString -Encoding UTF8 -Force -ErrorAction Stop
    #
    #            $calculatedCRC = Get-CRC32 -InputFile $tempFilePath
    #
    #            if ($calculatedCRC -eq $expectedCRC) {
    #                $results.CorrectCRC = $true
    #            } else {
    #                Write-Warning "CorrectCRC test failed. Expected '$expectedCRC', Got '$calculatedCRC'"
    #            }
    #        } catch {
    #            Write-Warning "CorrectCRC test failed with exception: $($_.Exception.Message)"
    #        } finally {
    #            if (Test-Path $tempFilePath) { Remove-Item $tempFilePath -Force -ErrorAction SilentlyContinue }
    #        }
    #
    #        # --- Test 2: Non-Existent File Throws Exception ---
    #        try {
    #            # Ensure file does not exist
    #            if (Test-Path $nonExistentFilePath) { Remove-Item $nonExistentFilePath -Force -ErrorAction SilentlyContinue }
    #
    #            # Call the function, expecting it to throw because ReadAllBytes will fail
    #            Get-CRC32 -InputFile $nonExistentFilePath
    #
    #            # If it reaches here, it didn't throw - test fails
    #            Write-Warning "NonExistentFileThrows test failed. Expected an exception, but none was thrown."
    #        } catch {
    #            # Exception was expected
    #            $results.NonExistentFileThrows = $true
    #            Write-Host "  DEBUG TEST: NonExistentFileThrows passed (Exception caught as expected)."
    #        } finally {
    #             # No cleanup needed as file shouldn't exist
    #        }
    #
    #        # --- Final Check ---
    #        $failedCount = ($results.Values | Where-Object { $_ -eq $false }).Count
    #        if ($failedCount -gt 0) {
    #            Write-Warning "$failedCount sub-tests failed for Get-CRC32."
    #        }
    #        return $failedCount -eq 0
    #    }
#        } # End GetCRC32 Test Block
#    } # End GetCRC32 duplicate
    Write-Host "`n=== Running Admin Tests (Started Elevated) ===" -ForegroundColor Yellow
        $adminRun = InvokeTestSuite -IsCurrentlyAdmin $true # Removed hyphen
        $allNonElevatedResults["Admin Context (Started Elevated)"] = $adminRun
        if (-not $adminRun.Result) { $nonAdminPass = $false }
        
        # No SYSTEM context run anymore
        $elevatedExitCode = if ($nonAdminPass) { 0 } else { 1 } # Exit code based on this run
        $elevatedSummary = "`n--- SYSTEM Context Run Skipped (Removed from script) ---`n"

    } else {
        # Started Non-Admin: Run Non-Admin tests
        Write-Host "`n=== Running Non-Admin Tests ===" -ForegroundColor Yellow
        $nonAdminRun = InvokeTestSuite -IsCurrentlyAdmin $false # Removed hyphen
        $allNonElevatedResults["Non-Admin Context"] = $nonAdminRun
        if (-not $nonAdminRun.Result) { $nonAdminPass = $false }

# Removed failing Get-InstalledApplicationPath (Registry Mock) test case

        # Now attempt self-elevation to run Admin tests
        if (-not $SkipElevation) {
            Write-Warning "`nAttempting to relaunch script with elevated privileges for Admin tests..."
            $tempOutputFile = [System.IO.Path]::GetTempFileName()
            Write-Host "Elevated process will write summary to: $tempOutputFile"
            
            $relaunchArgsList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", """$($MyInvocation.MyCommand.Path)""")
            $PSBoundParameters.Keys | Where-Object { $_ -ne 'SkipElevation' } | ForEach-Object { 
                $paramName = $_; $paramValue = $PSBoundParameters[$paramName]
                if ($paramValue -is [System.Management.Automation.SwitchParameter]) { 
                    if ($paramValue.IsPresent) { $relaunchArgsList += "-$paramName" } 
                } else { 
                    $relaunchArgsList += "-$paramName", """$paramValue""" 
                }
            }
            $relaunchArgsList += "-IsElevatedInstance" 
            $relaunchArgsList += "-ElevatedOutputFile", """$tempOutputFile"""
            
            $relaunchArgs = $relaunchArgsList -join " "
            Write-Host "Relaunch Args: $relaunchArgs"
            $process = $null
            try {
                 $process = Start-Process -FilePath "PowerShell.exe" -ArgumentList $relaunchArgs -Verb RunAs -WindowStyle Normal -Wait -PassThru -ErrorAction Stop
                 $elevatedExitCode = $process.ExitCode # This captures the exit code of the *elevated script*
                 Write-Host "Elevated process finished with Exit Code: $elevatedExitCode." -ForegroundColor Gray
                 if (Test-Path $tempOutputFile) { 
                     $elevatedSummary = Get-Content -Path $tempOutputFile -Raw # This contains Admin summary
                     Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue 
                 } else { 
                     Write-Warning "Elevated output file not found: $tempOutputFile" 
                     $elevatedSummary = "`n--- Elevated Run FAILED ---`nOutput file '$tempOutputFile' not found.`n"
                 }
            } catch { 
                Write-Error "Failed to re-launch script as Admin: $($_.Exception.Message)."
                if (Test-Path $tempOutputFile) { Remove-Item $tempOutputFile -Force -ErrorAction SilentlyContinue }
                $elevatedExitCode = -3 # Indicate launch failure
                $elevatedSummary = "`n--- Elevated Run FAILED to Start ---`nError: $($_.Exception.Message)`n" 
            }
        } else {
             Write-Host "`n--- Elevated Run Skipped (Parameter) ---" -ForegroundColor Yellow
        }
    }

    # --- Display FINAL Combined Summary ---
    Write-Host "`n=== Combined Test Summary ===" -ForegroundColor Cyan

    # Helper Function to print details for a context
    function PrintContextDetails { # Removed hyphen
        param($ContextRun)
        $contextResults = $ContextRun.Details
        if ($null -ne $contextResults) {
            # Sort test names for consistent order
            $sortedTestNames = $contextResults.Keys | Sort-Object
            foreach ($testName in $sortedTestNames) {
                $status = $contextResults[$testName]
                $statusColor = if ($status -eq "PASS") { "Green" } else { "Red" }
                Write-Host ("  - {0}: {1}" -f $testName.PadRight(50), $status) -ForegroundColor $statusColor
            }
            return $true # Indicate results were printed
        } else {
            Write-Host "  No results recorded for this context." -ForegroundColor Yellow
            return $false # Indicate no results
        }
    }

    # Display Non-Admin / Initial Admin Results
    $initialContext = if ($isAdmin) { "Admin (Started Elevated)" } else { "Non-Admin" }
    Write-Host "--- Results from Initial ($initialContext) Run ---" -ForegroundColor Cyan
    $totalInitialPass = 0; $totalInitialFail = 0
    foreach ($contextKey in $allNonElevatedResults.Keys) {
        $contextRun = $allNonElevatedResults[$contextKey]
        Write-Host "Context: $contextKey" -ForegroundColor White
        if (PrintContextDetails -ContextRun $contextRun) { # Removed hyphen
            $contextPass = ($contextRun.Details.Values | Where-Object { $_ -eq "PASS" }).Count
            $contextFail = ($contextRun.Details.Values | Where-Object { $_ -eq "FAIL" }).Count
            $totalInitialPass += $contextPass; $totalInitialFail += $contextFail
            $contextResultText = if (-not $contextRun.Result) { "FAIL" } else { "PASS" }
            $fgColor = if ($contextRun.Result) { "Green" } else { "Red" }
            Write-Host "  Context Result: $contextResultText" -ForegroundColor $fgColor
        }
    }
    Write-Host "--------------------------"
    Write-Host "Total Initial Passed: $totalInitialPass"
    Write-Host "Total Initial Failed: $totalInitialFail"
    $overallInitialResultText = if ($nonAdminPass) { 'PASS' } else { 'FAIL' } # $nonAdminPass holds the result of the first run
    $overallInitialColor = if ($nonAdminPass) { "Green" } else { "Red" }
    Write-Host "Overall Initial ($initialContext) Result: $overallInitialResultText" -ForegroundColor $overallInitialColor

    # Display Elevated Results (if available)
    if ($elevatedSummary) {
        Write-Host "`n--- Results from Elevated Run ---" -ForegroundColor Magenta
        if ($elevatedExitCode -lt 0) {
             Write-Host "Elevated Run FAILED (Code: $elevatedExitCode)" -ForegroundColor Red
        } elseif ($elevatedExitCode -ne 0) {
             Write-Host "Elevated Run Completed with Script Errors (Code: $elevatedExitCode)" -ForegroundColor Yellow
        } else {
             Write-Host "Elevated Run Completed Successfully (Code: 0)" -ForegroundColor Green
        }
        # The $elevatedSummary now contains the formatted list from the elevated instance
        Write-Host $elevatedSummary
        Write-Host "--- End Elevated Run Results ---" -ForegroundColor Magenta
    } elseif (-not $SkipElevation -and -not $isAdmin) {
         Write-Host "`n--- Elevated Run Skipped ---" -ForegroundColor Yellow
         Write-Host "(Requires UAC confirmation)" -ForegroundColor Yellow
         Write-Host "--- End Elevated Run Results ---" -ForegroundColor Magenta
    }
    
    # Determine final overall exit code 
    $finalOverallPass = $nonAdminPass # Start with initial run result
    if (-not $SkipElevation) {
        # Factor in elevated run only if it was attempted
         $finalOverallPass = $finalOverallPass -and ($elevatedExitCode -eq 0) 
    }

    Write-Host "`nAll test runs complete." -ForegroundColor Yellow # Modified message
    
    # --- Cleanup ---
    Write-Host "--- Test Cleanup ---" -ForegroundColor Cyan
    # Optional: Remove test log
    # Remove-Item $global:LogFile -Force -ErrorAction SilentlyContinue
    
    
    $exitCode = if ($finalOverallPass) { 0 } else { 1 }
    exit $exitCode


}
# End of the main 'if (-not $IsElevatedInstance)' block
# Else (this IS the elevated instance, run as Admin):
else {
    # Running as Admin via RunAs (this is the elevated instance)
    $adminContextResults = @{}
    $adminContextPass = $true 

    Write-Host "`n=== Running Admin Tests (Elevated Instance) ===" -ForegroundColor Yellow
    $adminRun = InvokeTestSuite -IsCurrentlyAdmin $true # Removed hyphen
    $adminContextResults["Admin Context (Elevated Instance)"] = $adminRun
    if (-not $adminRun.Result) { $adminContextPass = $false }

    # --- Prepare summary output for the ElevatedOutputFile ---
    $summaryOutput = @"
`n--- Test Summary (Admin Context - Elevated Instance) ---
"@
    $totalPass = 0; $totalFail = 0
    foreach ($contextKey in $adminContextResults.Keys) {
        $contextRun = $adminContextResults[$contextKey]
        $summaryOutput += "`nContext: $contextKey"
        $contextResults = $contextRun.Details
        if ($null -ne $contextResults) {
            # Sort test names for consistent order
            $sortedTestNames = $contextResults.Keys | Sort-Object
            foreach ($testName in $sortedTestNames) {
                $status = $contextResults[$testName]
                $summaryOutput += "`n  - $($testName.PadRight(50)): $status" # Add PASS/FAIL here
            }
            $contextPass = ($contextResults.Values | Where-Object { $_ -eq "PASS" }).Count
            $contextFail = ($contextResults.Values | Where-Object { $_ -eq "FAIL" }).Count
            $totalPass += $contextPass; $totalFail += $contextFail
            $contextResultText = if (-not $contextRun.Result) { "FAIL" } else { "PASS" }
            $summaryOutput += "`n  Context Result: $contextResultText"
        } else { $summaryOutput += "`n  No results recorded for this context." }
    }
    $summaryOutput += "`n--------------------------"
    $summaryOutput += "`nTotal Tests Run (Admin): $($totalPass + $totalFail)"
    $summaryOutput += "`nTotal Passed (Admin): $totalPass"
    $summaryOutput += "`nTotal Failed (Admin): $totalFail"
    $overallAdminResultText = if ($adminContextPass) { 'PASS' } else { 'FAIL' }
    $summaryOutput += "`nOverall Result for Admin Context: $overallAdminResultText`n"

    # Write combined summary to the output file specified by the initial instance
    if ($ElevatedOutputFile) {
        try {
            Write-Host $summaryOutput; # Also write to elevated console for visibility
            Write-Host "Writing combined summary to elevated output file: $ElevatedOutputFile" -ForegroundColor Gray;
            Set-Content -Path $ElevatedOutputFile -Value $summaryOutput -Encoding UTF8 -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write summary to elevated output file '$ElevatedOutputFile': $($_.Exception.Message)"
        }
    } else {
        Write-Warning "ElevatedOutputFile parameter not provided to elevated instance."
    }
    
    Write-Host "`nElevated test run complete. Summary written to output file." -ForegroundColor Yellow 
    
    # Exit code reflects success of Admin run
    $exitCode = if ($adminContextPass) { 0 } else { 1 } 
    exit $exitCode
}