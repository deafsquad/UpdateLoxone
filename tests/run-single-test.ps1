# Helper script for parallel test execution
# Called by Invoke-TestsParallel in run-tests.ps1 to run a single test file in an isolated process
# Outputs JSON result between ###RESULT_JSON### markers for the parent to parse
param(
    [Parameter(Mandatory)]
    [string]$TestFile,

    [string]$Verbosity = 'None'
)

$ErrorActionPreference = 'Continue'

# Set test environment variables
$env:PESTER_TEST_MODE = "1"
$env:PESTER_TEST_RUN = "1"
$env:LOXONE_TEST_MODE = "1"
$env:LOXONE_USE_FAST_NETWORK = "1"
$env:LOXONE_PARALLEL_MODE = "1"
$env:POWERSHELL_TELEMETRY_OPTOUT = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

$fileName = [System.IO.Path]::GetFileName($TestFile)
$startTime = Get-Date

try {
    # Import Pester
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop

    # Import LoxoneUtils module
    $testsRoot = Split-Path -Parent $PSScriptRoot
    if (-not $testsRoot -or -not (Test-Path (Join-Path $testsRoot 'LoxoneUtils'))) {
        $testsRoot = Split-Path -Parent (Split-Path -Parent $TestFile)
    }
    $modulePath = Join-Path $testsRoot 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    if (Test-Path $modulePath) {
        $Global:LoxoneUtilsPreloaded = $true
        $Global:LoxoneUtilsModulePath = $modulePath
        $Global:SuppressLoxoneToastInit = $true
        Import-Module $modulePath -Force -ErrorAction Stop
    }

    # Set up temp directory for test isolation
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterParallel_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $env:UPDATELOXONE_TEST_TEMP = $tempDir
    $Global:LogFile = Join-Path $tempDir 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null

    # Configure Pester
    $config = New-PesterConfiguration
    $config.Run.Path = @($TestFile)
    $config.Run.Exit = $false
    $config.Run.PassThru = $true
    $config.Output.Verbosity = $Verbosity

    # Run the test
    $result = Invoke-Pester -Configuration $config

    $duration = ((Get-Date) - $startTime).TotalMilliseconds

    # Collect failures
    $failures = @()
    if ($result.Failed) {
        foreach ($t in $result.Failed) {
            $failures += @{
                Name     = $t.ExpandedName
                Error    = "$($t.ErrorRecord.Exception.Message)"
                Duration = [math]::Round($t.Duration.TotalMilliseconds)
            }
        }
    }

    $jsonObj = @{
        FileName = $fileName
        File     = $TestFile
        Passed   = [int]$result.PassedCount
        Failed   = [int]$result.FailedCount
        Skipped  = [int]$result.SkippedCount
        Total    = [int]$result.TotalCount
        Duration = [math]::Round($duration)
        Failures = $failures
        Success  = ($result.FailedCount -eq 0)
    }

    # Output result between markers for parent process to parse
    $json = $jsonObj | ConvertTo-Json -Depth 4 -Compress
    Write-Output "###RESULT_JSON###"
    Write-Output $json
    Write-Output "###END_RESULT_JSON###"

    # Cleanup temp directory
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

} catch {
    $duration = ((Get-Date) - $startTime).TotalMilliseconds
    $jsonObj = @{
        FileName = $fileName
        File     = $TestFile
        Passed   = 0
        Failed   = 1
        Skipped  = 0
        Total    = 1
        Duration = [math]::Round($duration)
        Failures = @(@{
            Name     = "Script Error"
            Error    = "$($_.Exception.Message)"
            Duration = 0
        })
        Success  = $false
    }
    $json = $jsonObj | ConvertTo-Json -Depth 4 -Compress
    Write-Output "###RESULT_JSON###"
    Write-Output $json
    Write-Output "###END_RESULT_JSON###"
}
