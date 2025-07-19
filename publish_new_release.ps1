<#
.SYNOPSIS
Automates the process of packaging the UpdateLoxone script and generating winget manifest files.

.DESCRIPTION
This script performs the following actions:
1. Automatically determines the current version from existing winget manifests or defaults to 0.0.0.
2. Bumps the version (patch, then minor, then major, with rollover at .9 for patch/minor).
3. Takes publisher name as input.
4. Automatically determines author name from existing locale manifest or defaults to publisher name.
5. Packages the necessary files into an MSI installer, storing it locally in './releases_archive/'.
6. Calculates the SHA256 hash of the MSI installer.
7. Generates a multi-file winget manifest for the new version in the './manifests' directory.
8. Checks if CHANGELOG.md contains an entry for the new version; exits if not.
9. Stages README.md, CHANGELOG.md, and the new manifest files using Git (MSI files are not committed).
10. Commits the staged files with a message "Release vX.Y.Z".
11. Pushes the commit to the remote repository.
12. Creates a GitHub Tag and Release using 'gh' CLI.
13. Uploads the locally created MSI as an asset to the GitHub Release.
14. Updates the local installer manifest with the public URL of the uploaded asset.
15. Commits and pushes the updated installer manifest.
16. Rotates local MSI installers in './releases_archive/', keeping the latest 10.

.PARAMETER PackageIdentifier
(Required) The winget package identifier (e.g., YourGitHubUser.UpdateLoxone).

.PARAMETER DryRun
(Optional) If specified, the script will simulate most operations without making remote changes (no git push, no GitHub release creation/upload).

.PARAMETER WingetPkgsRepoPath
(Optional) The local file path to your cloned fork of the 'winget-pkgs' repository. Required if using -SubmitToWinget.

.PARAMETER SubmitToWinget
(Optional) If specified along with -WingetPkgsRepoPath, the script will copy manifests to your local 'winget-pkgs' clone, run 'winget validate', and prepare a local commit.

.PARAMETER SkipTests
(Optional) Skip running tests before release. USE WITH CAUTION - only for emergencies when tests are broken but release is needed.

.EXAMPLE
.\publish_new_release.ps1 -PackageIdentifier "deafsquad.UpdateLoxone"
.\publish_new_release.ps1 -PackageIdentifier "deafsquad.UpdateLoxone" -DryRun
.\publish_new_release.ps1 -PackageIdentifier "deafsquad.UpdateLoxone" -WingetPkgsRepoPath "D:\GitHub\winget-pkgs" -SubmitToWinget

.IMPORTANT
BEFORE RUNNING THIS SCRIPT:
1. Manually update 'CHANGELOG.md' to include a section for the new version that will be generated (e.g., "## [X.Y.Z] - YYYY-MM-DD"). The script will verify this.
2. Manually update 'README.md' if there are any changes to usage, features, etc.
3. Ensure you are in the root of your Git repository.
4. Ensure Git is installed and configured (including credentials for push).
5. Ensure GitHub CLI (`gh`) is installed and authenticated (`gh auth login`).
6. Ensure your working directory is clean or changes are committed/stashed.

.NOTES
The script automates most of the release process.
If any Git or GitHub CLI step fails, you may need to perform subsequent steps manually.
Local MSI installers are stored in './releases_archive/' and rotated (default: keep 10).
MSI files themselves are NOT committed to the Git repository; they are uploaded to GitHub Releases.
#>
[CmdletBinding()]
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] # Changed from $true
    [string]$PackageIdentifier, # Example: YourGitHubUser.UpdateLoxone. If not provided, script will attempt to auto-discover.

    [switch]$DryRun,
    [string]$WingetPkgsRepoPath,

    [switch]$SubmitToWinget,
    
    [switch]$SkipTests
)

if ([string]::IsNullOrWhiteSpace($PackageIdentifier)) {
    Write-Host "PackageIdentifier not provided, attempting auto-discovery..."
    $manifestsRoot = Join-Path -Path $PSScriptRoot -ChildPath "manifests"
    if (-not (Test-Path $manifestsRoot -PathType Container)) {
        Write-Error "Auto-discovery failed: Manifests directory '$manifestsRoot' not found."
        exit 1
    }

    $candidateFiles = @(Get-ChildItem -Path $manifestsRoot -Recurse -Filter "*.yaml" | Where-Object {
        $_.Name -notlike "*.installer.yaml" -and $_.Name -notlike "*.locale.*.yaml"
    })

    if ($candidateFiles.Count -eq 0) {
        Write-Error "Auto-discovery failed: No candidate version manifest YAML files found in '$manifestsRoot'."
        Write-Error "Ensure a version manifest (e.g., Publisher.Package.yaml) exists in the manifests subdirectory structure."
        exit 1
    } elseif ($candidateFiles.Count -gt 1) {
        Write-Host "Auto-discovery found multiple candidate version manifests. Attempting to find best match based on path..."
        $bestMatchIdentifier = $null
        foreach ($fileCand in $candidateFiles) {
            try {
                # Expected structure: $manifestsRoot/{char_publisher}/{publisher}/{package}/{publisher}.{package}.yaml
                $relativePath = $fileCand.DirectoryName.Substring($manifestsRoot.Length).TrimStart('\')
                $pathSegments = $relativePath.Split([System.IO.Path]::DirectorySeparatorChar)
                if ($pathSegments.Count -ge 3) { # Need at least char/publisher/package
                    $expectedPublisher = $pathSegments[-2]
                    $expectedPackage = $pathSegments[-1]
                    $derivedIdentifier = "$expectedPublisher.$expectedPackage"
                    if ($fileCand.BaseName -eq $derivedIdentifier) {
                        $bestMatchIdentifier = $fileCand.BaseName
                        Write-Host "Found strong candidate '$bestMatchIdentifier' where path matches filename structure."
                        break
                    }
                }
            } catch {
                Write-Warning "Error processing candidate file '$($fileCand.FullName)' for path matching: $($_.Exception.Message)"
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($bestMatchIdentifier)) {
            $PackageIdentifier = $bestMatchIdentifier
        } else {
            Write-Warning "Could not determine a single best match from multiple candidates based on path structure. Using the first one found: $($candidateFiles[0].BaseName)"
            $PackageIdentifier = $candidateFiles[0].BaseName
        }
    } else { # Exactly one candidate
        $PackageIdentifier = $candidateFiles[0].BaseName
    }
    
    if ([string]::IsNullOrWhiteSpace($PackageIdentifier)) {
        Write-Error "Auto-discovery failed to determine a valid PackageIdentifier from found files."
        exit 1
    }
    Write-Host "Auto-discovered PackageIdentifier: $PackageIdentifier"
} else {
    Write-Host "Using provided PackageIdentifier: $PackageIdentifier"
}

# --- Derive PublisherName and PackageName from PackageIdentifier ---
$IdParts = $PackageIdentifier.Split('.')
if ($IdParts.Count -lt 2) {
    Write-Error "PackageIdentifier '$PackageIdentifier' is not valid. It must be in the format 'Publisher.PackageName' (e.g., MyOrg.MyPackage)."
    exit 1
}
# Handles Publisher.With.Dots.PackageName by taking all but the last part as Publisher
$script:PublisherName = $IdParts[0..($IdParts.Count-2)] -join '.'
$script:PackageName = $IdParts[-1]

Write-Host "Using PackageIdentifier: $PackageIdentifier"
Write-Host "Derived Publisher: $script:PublisherName"
Write-Host "Derived Package Name: $script:PackageName"


if ($SubmitToWinget.IsPresent -and ([string]::IsNullOrWhiteSpace($WingetPkgsRepoPath) -or -not (Test-Path $WingetPkgsRepoPath -PathType Container))) {
    Write-Error "The -SubmitToWinget switch requires a valid -WingetPkgsRepoPath to be specified and the path must exist."
    exit 1
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- State Management Functions ---
$script:StateFile = Join-Path $PSScriptRoot ".release-progress"

function Get-ReleaseState {
    if (Test-Path $script:StateFile) {
        $content = Get-Content $script:StateFile -Raw
        $state = @{}
        foreach ($line in ($content -split "`n")) {
            $line = $line.Trim() -replace '[\r]+', ''  # Remove carriage returns
            if ($line -match "^([^=]+)=(.*)$") {
                # Clean both key and value from carriage returns
                $key = $matches[1].Trim() -replace '[\r\n]+', ''
                $value = $matches[2].Trim() -replace '[\r\n]+', ''
                $state[$key] = $value
            }
        }
        return $state
    }
    return @{}
}

function Set-ReleaseState {
    param(
        [string]$Key,
        [string]$Value
    )
    # Clean value from any carriage returns or newlines
    $Value = $Value.Trim() -replace '[\r\n]+', ''
    
    $state = Get-ReleaseState
    $state[$Key] = $Value
    $stateLines = @()
    foreach ($k in $state.Keys | Sort-Object) {
        # Clean each value when writing
        $cleanValue = $state[$k].Trim() -replace '[\r\n]+', ''
        $stateLines += "$k=$cleanValue"
    }
    Set-Content -Path $script:StateFile -Value ($stateLines -join "`n") -Force
}

function Clear-ReleaseState {
    if (Test-Path $script:StateFile) {
        Remove-Item $script:StateFile -Force
    }
}

# --- Check if we're resuming ---
$script:ResumeState = Get-ReleaseState
$script:IsResuming = $false
if ($script:ResumeState.Count -gt 0 -and $script:ResumeState.version) {
    Write-Host "Found previous release state for version $($script:ResumeState.version)" -ForegroundColor Yellow
    
    # In CI mode or if -Resume parameter exists, auto-resume
    if ($env:CI -or $env:RESUME_RELEASE -eq "true") {
        Write-Host "Auto-resuming release in CI/automated mode..." -ForegroundColor Green
        $script:IsResuming = $true
    } else {
        Write-Host "Do you want to resume the release? (Y/N)" -ForegroundColor Cyan
        $response = Read-Host
        if ($response -eq 'Y' -or $response -eq 'y') {
            $script:IsResuming = $true
            Write-Host "Resuming release process..." -ForegroundColor Green
        } else {
            Write-Host "Clearing previous state and starting fresh..." -ForegroundColor Yellow
            Clear-ReleaseState
            $script:ResumeState = @{}
        }
    }
}

# --- Function to Extract Changelog Notes for a Specific Version ---
function Get-ChangelogNotesForVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Version,

        [Parameter(Mandatory=$true)]
        [string]$ChangelogFilePath # Changed from AllChangelogLines
    )
    
    # Clean version string from any carriage returns or newlines
    $Version = $Version.Trim() -replace '[\r\n]+', ''

    Write-Host "Get-ChangelogNotesForVersion: Reading changelog from path '$ChangelogFilePath' for version '$Version'."
    if (-not (Test-Path $ChangelogFilePath)) {
        Write-Warning "Get-ChangelogNotesForVersion: Changelog file not found at '$ChangelogFilePath'."
        return "" # Return empty string if file not found
    }

    $AllChangelogLines = (Get-Content $ChangelogFilePath -Raw -ErrorAction SilentlyContinue) -split '\r?\n'
    if ($null -eq $AllChangelogLines -or $AllChangelogLines.Count -eq 0) {
        Write-Warning "Get-ChangelogNotesForVersion: Changelog file at '$ChangelogFilePath' is empty or could not be read properly."
        return "" # Return empty string if content is empty
    }
    Write-Host "Get-ChangelogNotesForVersion: Read $($AllChangelogLines.Count) lines from '$ChangelogFilePath'."

    $notesLines = [System.Collections.Generic.List[string]]::new()
    $collectingNotes = $false
    $escapedVersion = [regex]::Escape($Version)
    # Match version header with optional carriage returns/whitespace after version number
    $versionHeaderPattern = "^## \[$escapedVersion(?:\\r|\\n|\\s)*\]" # Pattern for the start of the target version's header
    $anyNewSectionPattern = "^## \[" # Pattern for the start of any ## section (typically a new version)

    Write-Host "Get-ChangelogNotesForVersion: Attempting to extract notes for version '$Version'."

    foreach ($line in $AllChangelogLines) {
        if ($collectingNotes) {
            # If we are collecting notes and encounter another ## section, it's the next version. Stop.
            if ($line -match $anyNewSectionPattern) {
                Write-Host "Get-ChangelogNotesForVersion: Found next section header, stopping collection for '$Version'."
                $collectingNotes = $false # Stop collecting
                break
            }
            # Otherwise, add the line to notes
            $notesLines.Add($line.TrimEnd())
        } elseif ($line -match $versionHeaderPattern) {
            # Found the header for the target version. Start collecting from the next line.
            Write-Host "Get-ChangelogNotesForVersion: Found header for version '$Version'. Starting to collect notes."
            $collectingNotes = $true
            # Do not add the header line itself to the notes
        }
    }

    if ($notesLines.Count -eq 0) {
        if ($collectingNotes) {
            # This means the header was found, but no lines followed before EOF or next section
            Write-Host "Get-ChangelogNotesForVersion: Version '$Version' header was found, but no subsequent content lines were collected."
        } else {
            # This means the header for $Version was never matched by $versionHeaderPattern
            Write-Warning "Get-ChangelogNotesForVersion: Header for version '$Version' not found in CHANGELOG.md. Cannot extract notes."
        }
    } else {
        Write-Host "Get-ChangelogNotesForVersion: Successfully collected $($notesLines.Count) lines of notes for version '$Version'."
    }

    return $notesLines -join "`n"
}
# --- Function to Get Current Version ---
function Get-CurrentVersion {
    param(
        [string]$BaseManifestPath # Path to the main package manifest (e.g., deafsquad.UpdateLoxone.yaml)
    )
    if (Test-Path $BaseManifestPath) {
        try {
            $lines = Get-Content $BaseManifestPath
            foreach ($line in $lines) {
                if ($line -match "^\s*PackageVersion:\s*(\d+\.\d+\.\d+)\s*$") {
                    $parsedVersion = $matches[1].Trim() -replace '[\r\n]+', ''
                    Write-Host "Found existing version in manifest: $parsedVersion"
                    return $parsedVersion
                }
            }
            Write-Warning "PackageVersion line not found or pattern mismatch in $BaseManifestPath. Defaulting to 0.0.0."
            return "0.0.0"
        } catch {
            Write-Warning "Error reading $BaseManifestPath. Defaulting to 0.0.0. Error: $($_.Exception.Message)"
            return "0.0.0"
        }
    } else {
        Write-Host "No existing manifest found at $BaseManifestPath. Assuming first release, starting from version 0.0.0."
        return "0.0.0"
    }
}

# --- Function to Increment Version ---
function Get-NextVersion {
    param(
        [string]$CurrentVersionString
    )
    # Clean the version string from any carriage returns or newlines
    $CurrentVersionString = $CurrentVersionString.Trim() -replace '[\r\n]+', ''
    $parts = $CurrentVersionString.Split('.')
    $major = [int]$parts[0]
    $minor = [int]$parts[1]
    $patch = [int]$parts[2]

    $patch++

    if ($patch -ge 10) {
        $patch = 0
        $minor++
        if ($minor -ge 10) {
            $minor = 0
            $major++
        }
    }
    $newVersion = "$major.$minor.$patch"
    Write-Host "Current version: $CurrentVersionString, New version: $newVersion"
    return $newVersion
}

# --- Function to Get Current Author ---
function Get-CurrentAuthor {
    param(
        [string]$LocaleManifestPath, 
        [string]$DefaultAuthor
    )
    if (Test-Path $LocaleManifestPath) {
        try {
            $lines = Get-Content $LocaleManifestPath
            foreach ($line in $lines) {
                if ($line -match "^\s*Author:\s*(.+?)\s*$") {
                    $parsedAuthor = $matches[1].Trim()
                    Write-Host "Found existing author in locale manifest: $parsedAuthor"
                    return $parsedAuthor
                }
            }
            Write-Warning "Author line not found or pattern mismatch in $LocaleManifestPath. Defaulting to '$DefaultAuthor'."
            return $DefaultAuthor
        } catch {
            Write-Warning "Error reading $LocaleManifestPath. Defaulting to '$DefaultAuthor'. Error: $($_.Exception.Message)"
            return $DefaultAuthor
        }
    } else {
        Write-Host "No existing locale manifest found at $LocaleManifestPath. Defaulting author to '$DefaultAuthor'."
        return $DefaultAuthor
    }
}

# --- Function to Rotate Local Release Archives ---
function Limit-LocalReleaseArchives {
    param(
        [string]$ArchiveDirectory,
        [int]$KeepCount = 10
    )
    Write-Host "Checking local release archives in '$ArchiveDirectory' to keep the latest $KeepCount..."
    if (-not (Test-Path $ArchiveDirectory)) {
        Write-Host "Archive directory '$ArchiveDirectory' does not exist. Skipping rotation."
        return
    }
    $archives = @(Get-ChildItem -Path $ArchiveDirectory -Filter "UpdateLoxone-v*.msi" | Sort-Object -Property Name -Descending)
    if ($archives.Count -gt $KeepCount) {
        $archivesToRemove = $archives | Select-Object -Skip $KeepCount
        foreach ($archiveToRemove in $archivesToRemove) {
            Write-Host "Removing old local archive: $($archiveToRemove.FullName)"
            Remove-Item -Path $archiveToRemove.FullName -Force
        }
    } else {
        Write-Host "Fewer than or equal to $KeepCount local archives found, or no archives found. No rotation needed."
    }
}


# --- Determine Manifest Paths ---
$manifestDir = Join-Path -Path $PSScriptRoot -ChildPath "manifests"
$publisherSubDir = Join-Path -Path $manifestDir -ChildPath $script:PublisherName.Substring(0,1).ToLower()
$packageSubDir = Join-Path -Path $publisherSubDir -ChildPath $script:PublisherName
$finalManifestDir = Join-Path -Path $packageSubDir -ChildPath $script:PackageName
$versionManifestPathForVersionDetection = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.yaml"
$localeManifestPathForAuthorDetection = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.locale.en-US.yaml"

# --- Determine and Bump Version ---
if ($script:IsResuming -and $script:ResumeState.version) {
    # Use the version from the saved state, removing any carriage returns
    $ScriptVersion = $script:ResumeState.version.Trim() -replace '[\r\n]+', ''
    $currentVersion = if ($script:ResumeState.current_version) { $script:ResumeState.current_version.Trim() -replace '[\r\n]+', '' } else { "0.0.0" }
    Write-Host "Resuming with version: $ScriptVersion (current: $currentVersion)" -ForegroundColor Yellow
} else {
    $currentVersion = Get-CurrentVersion -BaseManifestPath $versionManifestPathForVersionDetection
    $ScriptVersion = Get-NextVersion -CurrentVersionString $currentVersion
    # Save state (ensure no carriage returns)
    Set-ReleaseState -Key "version" -Value ($ScriptVersion.Trim() -replace '[\r\n]+', '')
    Set-ReleaseState -Key "current_version" -Value ($currentVersion.Trim() -replace '[\r\n]+', '')
}

# For dry runs, use an incremented version to avoid duplicate installations
# This prevents the same version being built with different ProductCodes
$isDryRunAutoIncremented = $false
if ($DryRun) {
    # Check if we've already done a dry run with this version
    $dryRunVersionFile = Join-Path $PSScriptRoot ".last-dryrun-version"
    if (Test-Path $dryRunVersionFile) {
        $lastDryRunVersion = (Get-Content $dryRunVersionFile -Raw).Trim() -replace '[\r\n]+', ''
        if ($lastDryRunVersion -eq $ScriptVersion) {
            # Increment version for this dry run
            $ScriptVersion = Get-NextVersion -CurrentVersionString $ScriptVersion
            Write-Host "DRY RUN: Using incremented version $ScriptVersion to avoid duplicate installation" -ForegroundColor Yellow
            $isDryRunAutoIncremented = $true
        }
    }
    # Save the version we're using for this dry run
    Set-Content -Path $dryRunVersionFile -Value $ScriptVersion -Force
}

# --- Determine Author Name ---
$AuthorName = Get-CurrentAuthor -LocaleManifestPath $localeManifestPathForAuthorDetection -DefaultAuthor $script:PublisherName

Write-Host "Starting release process for $script:PackageName version $ScriptVersion (Author: $AuthorName)..."

# --- Run Tests First ---
if ($script:IsResuming -and $script:ResumeState.ContainsKey("tests_completed") -and $script:ResumeState.tests_completed -eq "true") {
    Write-Host "Tests were already completed in previous run, skipping..." -ForegroundColor Green
} elseif ($SkipTests) {
    Write-Warning "SKIPPING TESTS - This is not recommended for production releases!"
    Write-Host ""
    Set-ReleaseState -Key "tests_completed" -Value "true"
    Set-ReleaseState -Key "tests_skipped" -Value "true"
} else {
    Write-Host "---"
    Write-Host "Running test suite before proceeding with release..."
$testScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "tests\run-tests.ps1"
if (-not (Test-Path $testScriptPath)) {
    Write-Error "Test runner script not found at: $testScriptPath"
    Write-Error "Cannot proceed with release without running tests."
    exit 1
}

try {
    Write-Host "Executing test suite with coverage analysis..."
    Write-Host "Test script path: $testScriptPath"
    Write-Host "Running command: & `"$testScriptPath`" -TestType All -Coverage -CI -LiveProgress -LogToFile"
    
    # Capture both output and error
    $testOutput = $null
    $testError = $null
    
    # Run all tests at once
    Write-Host "Running all tests (Unit, Integration, System)..." -ForegroundColor Cyan
    
    $testExitCode = 0
    
    try {
        # Run test script in a separate process to avoid strict mode and transcript issues
        Write-Host "DEBUG: Running test script: $testScriptPath" -ForegroundColor Yellow
        Write-Host "DEBUG: Current directory: $(Get-Location)" -ForegroundColor Yellow
        
        # Use Start-Process to run in a completely separate process
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = "powershell.exe"
        $pinfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$testScriptPath`" -TestType All -Coverage -CI -LiveProgress -LogToFile"
        $pinfo.UseShellExecute = $false
        $pinfo.RedirectStandardOutput = $false
        $pinfo.RedirectStandardError = $false
        $pinfo.WorkingDirectory = $PSScriptRoot
        
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
        
        $testExitCode = $p.ExitCode
        
        if ($testExitCode -ne 0) {
            Write-Warning "Tests failed with exit code: $testExitCode"
        } else {
            Write-Host "All tests passed successfully!" -ForegroundColor Green
        }
    } catch {
            Write-Host "DEBUG: Caught exception in test execution" -ForegroundColor Red
            Write-Host "DEBUG: Exception type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            Write-Host "DEBUG: Exception message: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "DEBUG: Target object: $($_.TargetObject)" -ForegroundColor Red
            if ($_.Exception.Message -like "*Count*") {
                Write-Host "DEBUG: This is the Count property error" -ForegroundColor Red
                Write-Host "DEBUG: Full error details:" -ForegroundColor Red
                Write-Host $_.Exception.ToString() -ForegroundColor Red
            }
            Write-Error "Error running tests: $_"
            $testExitCode = 1
        }
    
    # Coverage is already included in the main test run with -TestType All
    
    # Check for errors in output
    Write-Host "DEBUG: Checking for errors in output..." -ForegroundColor Cyan
    $errorFound = $false
    if ($testOutput) {
        Write-Host "DEBUG: testOutput exists, checking if array..." -ForegroundColor Cyan
        # Ensure testOutput is an array
        if ($testOutput -isnot [Array]) {
            Write-Host "DEBUG: Converting to array..." -ForegroundColor Cyan
            $testOutput = @($testOutput)
        }
        
        Write-Host "DEBUG: Starting foreach loop..." -ForegroundColor Cyan
        foreach ($line in $testOutput) {
            if ($line -is [System.Management.Automation.ErrorRecord]) {
                Write-Host "ERROR in test output: $($line.Exception.Message)" -ForegroundColor Red
                Write-Host "ERROR location: $($line.InvocationInfo.PositionMessage)" -ForegroundColor Red
                $errorFound = $true
            }
        }
        Write-Host "DEBUG: Foreach loop completed" -ForegroundColor Cyan
    }
    
    # Check if the test script executed successfully
    if ($testExitCode -ne 0 -or $errorFound) {
        Write-Error "Test execution failed with exit code: $testExitCode"
        Write-Error "Cannot proceed with release when tests fail."
        exit 1
    }
    
    # Look for the results JSON file
    $resultsDir = Join-Path (Split-Path $testScriptPath) "TestResults"
    $latestRun = Get-ChildItem -Path $resultsDir -Directory -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "TestRun_" } | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    
    if (-not $latestRun) {
        Write-Error "No test results directory found. Test execution may have failed."
        exit 1
    }
    
    $resultsFile = Join-Path $latestRun.FullName "test-results-summary.json"
    if (-not (Test-Path $resultsFile)) {
        Write-Error "Test results file not found at: $resultsFile"
        exit 1
    }
    
    try {
        $testResult = Get-Content $resultsFile -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse test results JSON: $_"
        exit 1
    }
    
    # Validate test result structure
    if (-not $testResult -or -not $testResult.Overall) {
        Write-Error "Test results file is missing expected structure"
        exit 1
    }
    
    Write-Host "---"
    Write-Host "Test Results Summary:"
    Write-Host "  Total Tests: $($testResult.Overall.Total)"
    Write-Host "  Passed: $($testResult.Overall.Passed)"
    Write-Host "  Failed: $($testResult.Overall.Failed)"
    Write-Host "  Skipped: $($testResult.Overall.Skipped)"
    Write-Host "  Pass Rate: $($testResult.Overall.PassRate)%"
    Write-Host "---"
    
    # Check for coverage report
    $coverageFile = Get-ChildItem -Path (Join-Path $resultsDir "coverage") -Filter "*.md" -ErrorAction SilentlyContinue | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    
    if ($coverageFile) {
        Write-Host "Coverage Report Generated: $($coverageFile.Name)"
        # Extract coverage percentage from filename (format: coverage_YYYYMMDD-HHMMSS_TTTT-CCC-SSS-DDD-EEE-FFF.md)
        if ($coverageFile.Name -match '_(\d{4})-(\d{3})-(\d{3})-(\d{3})-(\d{3})-(\d{3})\.md$') {
            $coveragePercent = $matches[2]
            Write-Host "  Function Coverage: $coveragePercent%"
        }
    }
    Write-Host "---"
    
    if ($testResult.Overall.Failed -gt 0) {
        Write-Error "Tests failed! Cannot proceed with release."
        Write-Error "Please fix the failing tests before attempting to release."
        exit 1
    }
    
    if ($testResult.Overall.Passed -eq 0) {
        Write-Error "No tests passed! This is suspicious. Cannot proceed with release."
        exit 1
    }
    
    Write-Host "All tests passed successfully! Proceeding with release..." -ForegroundColor Green
    Set-ReleaseState -Key "tests_completed" -Value "true"
} catch {
    Write-Host "DEBUG: Caught exception in test execution" -ForegroundColor Yellow
    Write-Host "DEBUG: Exception type: $($_.Exception.GetType().FullName)" -ForegroundColor Yellow
    Write-Host "DEBUG: Exception message: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "DEBUG: Target object: $($_.TargetObject)" -ForegroundColor Yellow
    
    # Check if this is the Count property error
    if ($_.Exception.Message -like "*Count*") {
        Write-Host "DEBUG: This is the Count property error" -ForegroundColor Magenta
        Write-Host "DEBUG: Full error details:" -ForegroundColor Magenta
        Write-Host $_ -ForegroundColor Magenta
    }
    
    Write-Error "Error running test suite: $_"
    Write-Error "Cannot proceed with release without successful test execution."
    exit 1
}
} # End of test execution block

# --- Pre-flight checks ---
$changelogPath = Join-Path -Path $PSScriptRoot -ChildPath "CHANGELOG.md"
if (-not (Test-Path $changelogPath)) {
    Write-Error "CHANGELOG.md not found at $changelogPath."
    exit 1
}

if ($script:IsResuming -and $script:ResumeState.ContainsKey("changelog_updated") -and $script:ResumeState.changelog_updated -eq "true") {
    Write-Host "CHANGELOG was already updated in previous run, skipping..." -ForegroundColor Green
    $changelogUpdatedByScript = $true
} else {
    $currentDateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $changelogLines = Get-Content $changelogPath -ErrorAction Stop
    # Clean any carriage returns from all lines
    $changelogLines = $changelogLines | ForEach-Object { $_.TrimEnd() -replace '[\r]+', '' }
    $unreleasedHeaderPatternStrict = "^## \[Unreleased\] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER$" # Strict match for replacement
    $unreleasedHeaderPatternLoose = "^## \[Unreleased\]" # Loose match for any [Unreleased] header
    $changelogUpdatedByScript = $false # Flag to track if script made changes

# Attempt to update [Unreleased] section first
for ($i = 0; $i -lt $changelogLines.Length; $i++) {
    if ($changelogLines[$i] -match $unreleasedHeaderPatternStrict) {
        Write-Host "Found '[Unreleased] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER'. Updating to version $ScriptVersion and timestamp $currentDateTime."
        $changelogLines[$i] = "## [$ScriptVersion] - $currentDateTime"
        Set-Content -Path $changelogPath -Value $changelogLines
        $changelogUpdatedByScript = $true
        break
    }
    elseif ($changelogLines[$i] -match $unreleasedHeaderPatternLoose) {
        # Fallback: Handle [Unreleased] without timestamp placeholder
        Write-Host "Found '[Unreleased]' header without timestamp placeholder. Updating to version $ScriptVersion and timestamp $currentDateTime."
        $changelogLines[$i] = "## [$ScriptVersion] - $currentDateTime"
        Set-Content -Path $changelogPath -Value $changelogLines
        $changelogUpdatedByScript = $true
        break
    }
    # Stop if we hit another version header, assuming Unreleased is at the top.
    # Allow processing if $i is 0 (first line) even if it's another version header (though unlikely for Unreleased)
    if ($i -gt 0 -and $changelogLines[$i] -match "^## \[") {
        break
    }
}

# Re-read content after potential modification
try {
    $changelogContent = Get-Content $changelogPath -Raw -ErrorAction Stop
} catch {
    Write-Error "Failed to read CHANGELOG.md: $_"
    exit 1
}
# Clean carriage returns from the content
$changelogContent = $changelogContent -replace '[\r]+', ''
$escapedVersionForRegex = [regex]::Escape($ScriptVersion)
$versionHeaderExactPattern = "## \[$escapedVersionForRegex\]" # Checks if the version section exists (with any date)
$versionHeaderWithSpecificPlaceholderPattern = "## \[$escapedVersionForRegex\]\s*-\s*YYYY-MM-DD_TIMESTAMP_PLACEHOLDER" # Checks for specific placeholder

if ($changelogUpdatedByScript) {
    Write-Host "CHANGELOG.md updated from '[Unreleased]' section for version $ScriptVersion."
    # The content is now up-to-date for $ScriptVersion.
} elseif ($changelogContent -match $versionHeaderWithSpecificPlaceholderPattern) {
    # [Unreleased] was not updated (or not found as specified),
    # but an entry for $ScriptVersion with the specific 'YYYY-MM-DD_TIMESTAMP_PLACEHOLDER' exists. Update its date.
    Write-Host "CHANGELOG.md contains an entry for version $ScriptVersion with 'YYYY-MM-DD_TIMESTAMP_PLACEHOLDER'. Updating timestamp."
    $lineToReplace = $matches[0]
    $newLine = "## [$ScriptVersion] - $currentDateTime" # Use the same $currentDateTime
    
    # Read lines again for replacement to ensure we have the latest content if other tools modified it (though unlikely here)
    $tempChangelogLinesForPlaceholderUpdate = Get-Content $changelogPath
    # Clean carriage returns
    $tempChangelogLinesForPlaceholderUpdate = $tempChangelogLinesForPlaceholderUpdate | ForEach-Object { $_.TrimEnd() -replace '[\r]+', '' }
    for ($j = 0; $j -lt $tempChangelogLinesForPlaceholderUpdate.Length; $j++) {
        if ($tempChangelogLinesForPlaceholderUpdate[$j] -eq $lineToReplace) {
            $tempChangelogLinesForPlaceholderUpdate[$j] = $newLine
            break
        }
    }
    Set-Content -Path $changelogPath -Value $tempChangelogLinesForPlaceholderUpdate
    $changelogContent = Get-Content $changelogPath -Raw # Re-read content again
    $changelogUpdatedByScript = $true # Mark as updated by script
    Write-Host "Updated specific placeholder date in CHANGELOG.md for version $ScriptVersion to $currentDateTime."
}

# Final check: After all attempts to update, does an entry for $ScriptVersion exist?
if (-not ($changelogContent -match $versionHeaderExactPattern)) {
    # Check if we have unpushed commits that will be processed by AI
    $currentBranch = git branch --show-current
    $unpushedCommits = git log "origin/$currentBranch..HEAD" --oneline 2>$null
    
    # For dry runs with auto-incremented versions, skip CHANGELOG requirement
    if ($DryRun -and $isDryRunAutoIncremented) {
        Write-Host "DRY RUN: Skipping CHANGELOG check for auto-incremented version $ScriptVersion" -ForegroundColor Yellow
    } elseif ($unpushedCommits) {
        Write-Host "CHANGELOG entry for version $ScriptVersion not found, but unpushed commits detected." -ForegroundColor Yellow
        Write-Host "The AI changelog verification will handle this during commit processing." -ForegroundColor Green
        $changelogUpdatedByScript = $false # Mark as not updated yet
    } else {
        Write-Error "CHANGELOG.md does not contain a valid entry for the new version $ScriptVersion after attempting updates."
        Write-Error "Please ensure an '## [Unreleased] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER' section is at the top, or a specific '## [$ScriptVersion] ...' entry exists."
        exit 1
    }
} else {
    # An entry for $ScriptVersion exists.
    if ($changelogUpdatedByScript) {
         Write-Host "CHANGELOG.md successfully prepared by script for version $ScriptVersion."
         Set-ReleaseState -Key "changelog_updated" -Value "true"
    } else {
        # This means an entry for $ScriptVersion was already present with a specific date (not the placeholder).
        Write-Host "CHANGELOG.md already contained a dated entry for version $ScriptVersion."
        Set-ReleaseState -Key "changelog_updated" -Value "true"
    }
}
} # End of changelog update section


$requiredFiles = @(
    ".\UpdateLoxone.ps1", ".\LoxoneUtils\LoxoneUtils.psd1", ".\ms.png", ".\nok.png", ".\ok.png",
    ".\UpdateLoxoneMSList.txt.example", ".\Send-GoogleChat.ps1", ".\README.md", ".\CHANGELOG.md"
)
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) { Write-Error "Required file not found: $file."; exit 1 }
}
Write-Host "All required project files seem to be present."
Write-Host "IMPORTANT: Ensure you have manually updated README.md if necessary for version $ScriptVersion."

# --- Define Archive Path ---
if ($DryRun) {
    $releasesArchiveDirName = "dryrun_archive"
    $releasesArchiveDir = Join-Path -Path $PSScriptRoot -ChildPath $releasesArchiveDirName
    Write-Host "DRY RUN: Using dry run archive directory: $releasesArchiveDir" -ForegroundColor Yellow
} else {
    $releasesArchiveDirName = "releases_archive"
    $releasesArchiveDir = Join-Path -Path $PSScriptRoot -ChildPath $releasesArchiveDirName
}

if (-not (Test-Path $releasesArchiveDir)) {
    Write-Host "Creating local releases archive directory: $releasesArchiveDir"
    New-Item -ItemType Directory -Path $releasesArchiveDir | Out-Null
}

# --- Create MSI Package ---
Write-Host "Checking for PSMSI module..."
if (-not (Get-Module -ListAvailable -Name PSMSI)) {
    Write-Host "Installing PSMSI module..."
    Install-Module -Name PSMSI -Force -Scope CurrentUser
}
Import-Module PSMSI -Force

$msiFileName = "UpdateLoxone-v$ScriptVersion.msi"
$msiFilePath = Join-Path -Path $releasesArchiveDir -ChildPath $msiFileName

if ($script:IsResuming -and $script:ResumeState.ContainsKey("msi_created") -and $script:ResumeState.msi_created -eq "true" -and (Test-Path -LiteralPath $msiFilePath)) {
        Write-Host "MSI installer already exists from previous run, skipping creation..." -ForegroundColor Green
        # Load the hash from state
        if ($script:ResumeState.msi_hash) {
            $fileHash = $script:ResumeState.msi_hash
            Write-Host "Using saved SHA256 hash: $fileHash" -ForegroundColor Gray
        } else {
            # Recalculate if not in state
            Write-Host "Recalculating SHA256 hash..." -ForegroundColor Yellow
            $fileHash = Get-FileHash -Path $msiFilePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        }
} else {
    Write-Host "Creating MSI installer: $msiFilePath..."
    try {
    # Create stable GUIDs for proper upgrade behavior
    # UpgradeCode must be the same for all versions to enable upgrades
    $upgradeCode = [guid]'1a73a1be-50e6-4e92-af03-586f4a9d9e82'
    
    # PSMSI generates ProductCode automatically based on ProductName + Version
    # The stable UpgradeCode ensures proper upgrade behavior
    
    # Create MSI with simplified syntax
    # Ensure OutputDirectory is a DirectoryInfo object
    $outputDir = Get-Item -Path $releasesArchiveDir
    
    # PSMSI doesn't support $using: variables, so we'll use script scope
    
    <# Old splatting approach - keeping for reference
    $installerParams = @{
        ProductName = $script:PackageName
        UpgradeCode = $upgradeCode
        Version = [version]$ScriptVersion
        Manufacturer = $script:PublisherName
        Description = "Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers."
        OutputDirectory = $outputDir
        Content = {
            # Install to Program Files
            New-InstallerDirectory -PredefinedDirectory "ProgramFilesFolder" -Content {
                New-InstallerDirectory -DirectoryName "UpdateLoxone" -Content {
                    # Main script
                    New-InstallerFile -Source "$PSScriptRoot\UpdateLoxone.ps1"
                    
                    # Modules folder
                    New-InstallerDirectory -DirectoryName "LoxoneUtils" -Content {
                        $moduleFiles = Get-ChildItem "$PSScriptRoot\LoxoneUtils" -Filter "*.ps*" -File
                        foreach ($file in $moduleFiles) {
                            New-InstallerFile -Source $file.FullName
                        }
                    }
                    
                    # Assets
                    New-InstallerFile -Source "$PSScriptRoot\ms.png"
                    New-InstallerFile -Source "$PSScriptRoot\ok.png"
                    New-InstallerFile -Source "$PSScriptRoot\nok.png"
                    
                    # Documentation
                    New-InstallerFile -Source "$PSScriptRoot\README.md"
                    New-InstallerFile -Source "$PSScriptRoot\CHANGELOG.md"
                    
                    # Example config
                    New-InstallerFile -Source "$PSScriptRoot\UpdateLoxoneMSList.txt.example"
                    
                    # Google Chat script if it exists
                    $googleChatScript = "$PSScriptRoot\Send-GoogleChat.ps1"
                    if (Test-Path $googleChatScript) {
                        New-InstallerFile -Source $googleChatScript
                    }
                }
            }
            
            # Create Start Menu shortcut
            New-InstallerDirectory -PredefinedDirectory "ProgramMenuFolder" -Content {
                New-InstallerDirectory -DirectoryName $script:PackageName -Content {
                    New-InstallerShortcut -Name $script:PackageName `
                        -Target "powershell.exe" `
                        -Arguments "-ExecutionPolicy Bypass -File `"[ProgramFilesFolder]$script:PackageName\UpdateLoxone.ps1`"" `
                        -WorkingDirectory "[ProgramFilesFolder]$script:PackageName" `
                        -Description "Automatically update Loxone software"
                }
            }
        }
    }
    #>
    
    # Direct call without splatting to avoid parameter binding issues
    Write-Host "DEBUG: ProductName=$($script:PackageName), Version=$ScriptVersion" -ForegroundColor Yellow
    Write-Host "DEBUG: OutputDir=$($outputDir.FullName)" -ForegroundColor Yellow
    
    New-Installer -ProductName "$script:PackageName" `
        -UpgradeCode $upgradeCode `
        -Version ([version]$ScriptVersion) `
        -Manufacturer $script:PublisherName `
        -Description "Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers." `
        -OutputDirectory $outputDir `
        -RequiresElevation `
        -Content {
            New-InstallerDirectory -PredefinedDirectory "ProgramFilesFolder" -Content {
                New-InstallerDirectory -DirectoryName "UpdateLoxone" -Id "INSTALLFOLDER" -Content {
                    # Main script - using literal path with ID for shortcut
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\UpdateLoxone.ps1" -Id "MainScript"
                    
                    # Modules
                    New-InstallerDirectory -DirectoryName "LoxoneUtils" -Content {
                        $modDir = "C:\Users\deafs_iutw2w3\UpdateLoxone\LoxoneUtils"
                        Get-ChildItem $modDir -Filter "*.ps*" -File | ForEach-Object {
                            New-InstallerFile -Source $_.FullName
                        }
                    }
                    
                    # Assets
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\ms.png"
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\ok.png"
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\nok.png"
                    
                    # Documentation
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\README.md"
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\CHANGELOG.md"
                    
                    # Example configuration
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\UpdateLoxoneMSList.txt.example"
                    
                    # Google Chat script
                    New-InstallerFile -Source "C:\Users\deafs_iutw2w3\UpdateLoxone\Send-GoogleChat.ps1"
                }
            }
            
            # Create Start Menu shortcut
            New-InstallerDirectory -PredefinedDirectory "ProgramMenuFolder" -Content {
                New-InstallerDirectory -DirectoryName "UpdateLoxone" -Content {
                    New-InstallerShortcut -Name "UpdateLoxone" `
                        -FileId "MainScript" `
                        -Description "Automatically update Loxone software"
                }
            }
        }
    
    <# Commented out duplicate call
    New-Installer `
        -ProductName $script:PackageName `
        -UpgradeCode $upgradeCode `
        -Version ([version]$ScriptVersion) `
        -Manufacturer $script:PublisherName `
        -Description "Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers." `
        -OutputDirectory $outputDir `
        -RequiresElevation `
        -Content {
            # Install to Program Files
            New-InstallerDirectory -PredefinedDirectory "ProgramFilesFolder" -Content {
                New-InstallerDirectory -DirectoryName $script:PackageName -Content {
                    # Main script
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "UpdateLoxone.ps1")
                    
                    # Modules folder
                    New-InstallerDirectory -DirectoryName "LoxoneUtils" -Content {
                        $moduleFiles = Get-ChildItem (Join-Path $PSScriptRoot "LoxoneUtils") -Filter "*.ps*" -File
                        foreach ($file in $moduleFiles) {
                            New-InstallerFile -Source $file.FullName
                        }
                    }
                    
                    # Assets
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "ms.png")
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "ok.png")
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "nok.png")
                    
                    # Documentation
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "README.md")
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "CHANGELOG.md")
                    
                    # Example config
                    New-InstallerFile -Source (Join-Path $PSScriptRoot "UpdateLoxoneMSList.txt.example")
                    
                    # Google Chat script if it exists
                    $googleChatScript = Join-Path $PSScriptRoot "Send-GoogleChat.ps1"
                    if (Test-Path $googleChatScript) {
                        New-InstallerFile -Source $googleChatScript
                    }
                }
            }
            
            # Create Start Menu shortcut
            New-InstallerDirectory -PredefinedDirectory "ProgramMenuFolder" -Content {
                New-InstallerDirectory -DirectoryName $script:PackageName -Content {
                    New-InstallerShortcut -Name $script:PackageName `
                        -Target "powershell.exe" `
                        -Arguments "-ExecutionPolicy Bypass -File `"[ProgramFilesFolder]$script:PackageName\UpdateLoxone.ps1`"" `
                        -WorkingDirectory "[ProgramFilesFolder]$script:PackageName" `
                        -Description "Automatically update Loxone software"
                }
            }
        }
    #>
    
    # PSMSI creates files with pattern: ProductName.Version.Architecture.msi
    try {
        # PSMSI creates files with pattern: ProductName.Version.Architecture.msi
        $actualMsiPath = Join-Path $releasesArchiveDir "$script:PackageName.$ScriptVersion.x86.msi"
    
    # Rename to our expected filename
    if (Test-Path -LiteralPath $actualMsiPath) {
        Move-Item -Path $actualMsiPath -Destination $msiFilePath -Force
        Write-Host "Successfully found and renamed MSI installer: $msiFilePath"
    } else {
        # Check for x64 version
        $actualMsiPath = Join-Path $releasesArchiveDir "$script:PackageName.$ScriptVersion.x64.msi"
        
        if (Test-Path -LiteralPath $actualMsiPath) {
            Move-Item -Path $actualMsiPath -Destination $msiFilePath -Force
            Write-Host "Successfully created MSI installer: $msiFilePath"
        } else {
            # More detailed error with actual files found
            $foundMsis = Get-ChildItem -Path $releasesArchiveDir -Filter "*.msi" | Select-Object -ExpandProperty Name
            if ($foundMsis) {
                throw "ERROR: Could not find MSI package created by PSMSI. Expected $script:PackageName.$ScriptVersion.x86.msi or x64.msi but found: $($foundMsis -join ', ')"
            } else {
                throw "ERROR: No MSI files found in archive directory. PSMSI may have failed to create the installer."
            }
        }
    }
    
    } catch {
        Write-Error "Error during MSI file detection: $($_.Exception.Message)"
        throw
    }
    
    # Clean up WiX intermediate files
    Write-Host "Cleaning up build artifacts..."
    Get-ChildItem -Path $releasesArchiveDir -Filter "*.wxs" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $releasesArchiveDir -Filter "*.wxsobj" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $releasesArchiveDir -Filter "*.wixpdb" | Remove-Item -Force -ErrorAction SilentlyContinue
} catch {
    Write-Error "Failed to create MSI installer: $($_.Exception.Message)"
    Write-Error "Exception type: $($_.Exception.GetType().FullName)"
    Write-Error "Full error: $_"
    if ($_.Exception.InnerException) {
        Write-Error "Inner exception: $($_.Exception.InnerException.Message)"
    }
    exit 1
}

    # --- Calculate SHA256 Hash ---
    Write-Host "Calculating SHA256 hash for $msiFilePath..."
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        $fileHash = Get-FileHash -Path $msiFilePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    } else {
        # Fallback for older PowerShell versions
        $sha256 = New-Object System.Security.Cryptography.SHA256Managed
        $fileBytes = [System.IO.File]::ReadAllBytes($msiFilePath)
        $hashBytes = $sha256.ComputeHash($fileBytes)
        $fileHash = [BitConverter]::ToString($hashBytes).Replace('-', '')
        $sha256.Dispose()
    }
    Write-Host "SHA256 Hash: $fileHash"
    
    # Save MSI creation state
    Set-ReleaseState -Key "msi_created" -Value "true"
    Set-ReleaseState -Key "msi_hash" -Value $fileHash
} # End of MSI creation section

# --- Create Manifests ---
$versionManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.yaml"
$localeManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.locale.en-US.yaml"
$installerManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.installer.yaml"

if ($script:IsResuming -and $script:ResumeState.ContainsKey("manifests_created") -and $script:ResumeState.manifests_created -eq "true") {
    Write-Host "Manifests were already created in previous run, skipping..." -ForegroundColor Green
} else {
    $currentDate = Get-Date -Format "yyyy-MM-dd"
$versionManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@
Set-Content -Path $versionManifestPath -Value $versionManifestContent -Encoding UTF8

$localeManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
PackageLocale: en-US
Publisher: $script:PublisherName
Author: $AuthorName
PackageName: $script:PackageName
PackageUrl: https://github.com/$script:PublisherName/$script:PackageName
License: MIT
LicenseUrl: https://github.com/$script:PublisherName/$script:PackageName/blob/main/LICENSE
ShortDescription: Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers.
Moniker: updateloxone
Tags:
  - loxone
  - automation
  - update
  - smart-home
ReleaseDate: $currentDate
ManifestType: locale
ManifestVersion: 1.6.0
"@
Set-Content -Path $localeManifestPath -Value $localeManifestContent -Encoding UTF8

# Construct the predictable GitHub release URL
$InstallerUrl = "https://github.com/$script:PublisherName/$script:PackageName/releases/download/v$ScriptVersion/$msiFileName"
Write-Host "Using predictable installer URL: $InstallerUrl" -ForegroundColor Cyan

$installerManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
InstallerLocale: en-US
InstallerType: msi
Installers:
  - Architecture: x64
    InstallerUrl: $InstallerUrl
    InstallerSha256: $fileHash
    ProductCode: '{00000000-0000-0000-0000-000000000000}'
ManifestType: installer
ManifestVersion: 1.6.0
"@
Set-Content -Path $installerManifestPath -Value $installerManifestContent -Encoding UTF8
Write-Host "Winget manifests created in: $finalManifestDir"
    
    # Save manifest creation state
    Set-ReleaseState -Key "manifests_created" -Value "true"
} # End of manifest creation section

# --- Git and GitHub CLI Operations ---
Write-Host "---"
Write-Host "Attempting Git and GitHub CLI operations..."
try {
    Get-Command git -ErrorAction Stop | Out-Null; Write-Host "Git command found."
    if (-not $DryRun) { # gh is only needed for actual remote operations
        Get-Command gh -ErrorAction Stop | Out-Null; Write-Host "GitHub CLI (gh) command found."
    }
} catch {
    Write-Warning "Git command not found, or GitHub CLI (gh) not found (and not a DryRun). Skipping automated Git/GitHub operations."
    # For DryRun, gh not being found is not critical. For a real run, it is.
    if (-not $DryRun) {
        exit 1 # Critical for full automation if not a dry run
    }
}

$commitMessage = "Release v$ScriptVersion"
$tagName = "v$ScriptVersion"
$readmeRelativePath = ".\README.md"
$changelogRelativePath = ".\CHANGELOG.md"
$installerManifestRelativePath = $installerManifestPath.Replace($PSScriptRoot, ".")

# Initialize flags
$script:CreateFreshCommit = $false

try {
    # Check for uncommitted changes first
    $uncommittedChanges = git status --porcelain 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Git status failed: $uncommittedChanges"
        Write-Error "Cannot determine repository state."
        exit 1
    }
    
    if ($uncommittedChanges) {
        Write-Host "`nUncommitted changes detected:" -ForegroundColor Yellow
        git status --short
        Write-Host "`nThese changes will be included in the release commit." -ForegroundColor Green
    }
    
    # Check for unpushed commits and handle changelog verification
    $currentBranch = git branch --show-current
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($currentBranch)) {
        Write-Error "Failed to get current branch name"
        exit 1
    }
    
    $unpushedCommits = git log "origin/$currentBranch..HEAD" --oneline 2>$null
    # Note: git log returns exit code 0 even when no commits found, so we check the output instead
    
    if ($unpushedCommits -and -not $DryRun) {
        Write-Host "`nFound unpushed commits that will be combined into the release:" -ForegroundColor Yellow
        $unpushedCommits | ForEach-Object { Write-Host "  $_" }
        
        # Get detailed commit messages
        $commitMessages = git log "origin/$currentBranch..HEAD" --pretty=format:"%s%n%n%b" --reverse
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to get commit messages"
            exit 1
        }
        
        # Get full diff from origin to current HEAD
        Write-Host "Getting full diff from origin/$currentBranch to HEAD..." -ForegroundColor Gray
        $gitDiff = git diff "origin/$currentBranch..HEAD" 2>&1
        
        # Check if git diff failed
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Git diff failed with exit code $LASTEXITCODE"
            Write-Error "Error: $gitDiff"
            Write-Error "Cannot proceed without diff analysis."
            exit 1
        }
        
        # Log diff size for diagnostics
        $diffSizeKB = [Math]::Round($gitDiff.Length / 1024, 2)
        Write-Host "Git diff size: $diffSizeKB KB" -ForegroundColor Gray
        
        # Read entire CHANGELOG
        try {
            $changelogContent = Get-Content $changelogPath -Raw -ErrorAction Stop
        } catch {
            Write-Error "Failed to read CHANGELOG.md for AI analysis: $_"
            exit 1
        }
        
        Write-Host "`nPreparing comprehensive changelog analysis..." -ForegroundColor Cyan
        
        # Create AI prompt with full context
        $aiPrompt = @"
You are creating a comprehensive CHANGELOG entry for all changes between the last published release and current development state.

=== COMMIT MESSAGES ===
$commitMessages

=== CODE CHANGES (git diff) ===
$gitDiff

=== CURRENT CHANGELOG ===
$changelogContent

=== INSTRUCTIONS ===
1. Analyze ALL changes shown in the git diff and commit messages
2. Create a complete Unreleased section that captures ALL significant changes
3. Follow Keep a Changelog format (https://keepachangelog.com/):
   - Use ### Added, ### Changed, ### Fixed, ### Removed, ### Deprecated, ### Security sections as needed
   - Write clear, user-facing descriptions (not technical implementation details)
   - Group related changes together
   - Use past tense
   - Focus on WHAT changed and WHY it matters to users
4. Include changes that are already in the current Unreleased section (consolidate everything)
5. Do NOT include changes that are already documented in versioned releases

IMPORTANT: You must capture ALL changes shown in the diff, not just what's in commit messages.

RESPOND WITH:
UPDATED_CHANGELOG
## [Unreleased] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Added
- New features...

### Changed
- Changes to existing functionality...

### Fixed
- Bug fixes...

(include all relevant sections)
END_CHANGELOG
"@

        # Call Claude directly using CLI
        Write-Host "`nCalling Claude to verify changelog..." -ForegroundColor Cyan
        
        try {
            # Check if claude command is available
            $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
            if (-not $claudeCmd) {
                Write-Warning "Claude CLI not found. Please install it or ensure it's in PATH."
                Write-Host "Manual verification required. Saving prompt to file..." -ForegroundColor Yellow
                $promptFile = Join-Path $PSScriptRoot "ai_changelog_prompt.txt"
                Set-Content -Path $promptFile -Value $aiPrompt -Encoding UTF8
                Write-Host "Prompt saved to: $promptFile" -ForegroundColor Green
                Write-Host "Please manually verify with Claude and update CHANGELOG if needed." -ForegroundColor Yellow
                $aiResponse = "NO_CHANGE_NEEDED"  # Default to no change if Claude not available
            } else {
                # Save prompt to temp file for piping
                $tempPromptFile = Join-Path $env:TEMP "changelog_prompt_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
                Set-Content -Path $tempPromptFile -Value $aiPrompt -Encoding UTF8
                
                # Call Claude with the prompt
                Write-Host "Querying Claude for changelog verification..." -ForegroundColor Gray
                Write-Host "Prompt size: $([Math]::Round($aiPrompt.Length / 1024, 2)) KB" -ForegroundColor Gray
                
                # Capture both stdout and stderr
                $claudeError = $null
                $aiResponse = Get-Content $tempPromptFile -Raw | & claude -p 'Process this changelog verification request and respond EXACTLY as instructed' --output-format text 2>&1 | Out-String
                
                # Check if claude command failed
                if ($LASTEXITCODE -ne 0) {
                    $claudeError = $aiResponse
                    throw "Claude command failed with exit code $LASTEXITCODE. Error: $claudeError"
                }
                
                # Clean up temp file
                if (Test-Path $tempPromptFile) {
                    Remove-Item $tempPromptFile -Force
                }
                
                if ([string]::IsNullOrWhiteSpace($aiResponse)) {
                    throw "Claude returned empty response. This may indicate the prompt was too large or there was a processing error."
                }
            }
        } catch {
            Write-Error "Error calling Claude: $_"
            Write-Host "Prompt size was: $([Math]::Round($aiPrompt.Length / 1024, 2)) KB" -ForegroundColor Yellow
            Write-Host "Git diff size was: $diffSizeKB KB" -ForegroundColor Yellow
            
            # Save the prompt for manual processing
            $errorPromptFile = Join-Path $PSScriptRoot "ai_changelog_prompt_error.txt"
            Set-Content -Path $errorPromptFile -Value $aiPrompt -Encoding UTF8
            Write-Host "Full prompt saved to: $errorPromptFile" -ForegroundColor Yellow
            
            Write-Error "Cannot proceed without changelog verification. Please:"
            Write-Error "1. Check if prompt size is too large for Claude"
            Write-Error "2. Manually process the prompt saved at: $errorPromptFile"
            Write-Error "3. Update CHANGELOG.md manually and run the script again"
            exit 1
        }
        
        # Process AI response - we always expect an updated changelog with full diff analysis
        if ($aiResponse -match '(?s)UPDATED_CHANGELOG(.*)END_CHANGELOG') {
            $newChangelogSection = $matches[1].Trim()
            Write-Host "`nUpdating CHANGELOG.md with comprehensive AI analysis..." -ForegroundColor Yellow
            
            # Replace the Unreleased section completely
            if ($changelogContent -match '(?s)(.*?)(## \[Unreleased\][^#]*?)(## \[\d)') {
                # Found Unreleased section followed by a version
                $before = $matches[1]
                $after = $matches[3]
                $updatedChangelog = $before + $newChangelogSection + "`n`n" + $after
            } elseif ($changelogContent -match '(?s)(.*?)(## \[Unreleased\].*)$') {
                # Found Unreleased section at the end
                $before = $matches[1]
                $updatedChangelog = $before + $newChangelogSection
            } else {
                # No Unreleased section found, add it after the header
                $updatedChangelog = $changelogContent -replace '(# Changelog.*?(?:\r?\n){2,})', "`$1$newChangelogSection`n`n"
            }
            
            Set-Content -Path $changelogPath -Value $updatedChangelog -Encoding UTF8 -NoNewline
            Write-Host "CHANGELOG.md updated with complete analysis of all changes." -ForegroundColor Green
        }
        else {
            Write-Warning "Claude did not return expected UPDATED_CHANGELOG format."
            Write-Warning "Response: $($aiResponse.Substring(0, [Math]::Min(200, $aiResponse.Length)))..."
            Write-Host "Proceeding with existing CHANGELOG. You may need to update it manually." -ForegroundColor Yellow
        }
        
        # Perform the squash using soft reset approach (simpler and more reliable)
        Write-Host "`nAutomatically combining all unpushed commits into one release commit..." -ForegroundColor Cyan
        
        # Get the number of commits to squash
        $commitCount = @($unpushedCommits).Count
        
        if ($commitCount -gt 0) {
            Write-Host "Combining $commitCount commit(s) with release changes..." -ForegroundColor Gray
            
            # Soft reset to before all unpushed commits (keeps all changes staged)
            git reset --soft "origin/$currentBranch"
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Git reset failed with exit code $LASTEXITCODE"
                Write-Error "Cannot proceed with commit squashing."
                exit 1
            }
            
            Write-Host "All changes are now staged for a single release commit." -ForegroundColor Green
            
            # Set a flag to indicate we should create a fresh commit
            $script:CreateFreshCommit = $true
        }
    }
    
    # Check if we've already committed
    if ($script:IsResuming -and $script:ResumeState.ContainsKey("commit_created") -and $script:ResumeState.commit_created -eq "true") {
        Write-Host "Release commit was already created in previous run..." -ForegroundColor Green
        $releaseCommitHash = $script:ResumeState.commit_hash
        Write-Host "Using saved commit hash: $releaseCommitHash" -ForegroundColor Gray
        
        # Check if it's been pushed
        if ((-not $script:ResumeState.ContainsKey("commit_pushed") -or $script:ResumeState.commit_pushed -ne "true") -and -not $DryRun) {
            Write-Host "Commit/tag not yet pushed, attempting push..." -ForegroundColor Yellow
            git push --follow-tags
            if ($LASTEXITCODE -eq 0) {
                Set-ReleaseState -Key "commit_pushed" -Value "true"
                Set-ReleaseState -Key "tag_pushed" -Value "true"
                Write-Host "Git push successful (commit and tag)." -ForegroundColor Green
            } else {
                Write-Error "Git push failed with exit code: $LASTEXITCODE"
                Write-Error "You may need to run: git push --set-upstream origin <current-branch> --follow-tags"
                exit 1
            }
        }
    } else {
        # Check for untracked files first
        Write-Host "Checking for untracked files..."
        $untrackedFiles = git ls-files --others --exclude-standard 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to check for untracked files: $untrackedFiles"
            exit 1
        }
    
    if ($untrackedFiles -and $untrackedFiles -is [string[]]) {
        Write-Host "`nThe following untracked files were found:" -ForegroundColor Yellow
        $untrackedFiles | ForEach-Object { Write-Host "  - $_" }
        
        if (-not $DryRun) {
            # In CI/automated mode, skip untracked files prompt
            if ($env:RESUME_RELEASE -eq 'true' -or $script:IsResuming) {
                Write-Host "CI/Automated mode: Ignoring untracked files (not including them in release)" -ForegroundColor Yellow
                # Don't exit, just continue without including untracked files
            } else {
                Write-Host "`nDo you want to include these files in the release? (Y/N)" -ForegroundColor Cyan
                $response = Read-Host
                
                if ($response -ne 'Y' -and $response -ne 'y') {
                    Write-Host "Aborting release. Please handle untracked files manually:" -ForegroundColor Yellow
                    Write-Host "  - Add them to .gitignore if they should be ignored"
                    Write-Host "  - Delete them if they're temporary files"
                    Write-Host "  - Commit them separately if they're needed but not for this release"
                    exit 1
                }
            }
        } else {
            Write-Host "DRY RUN: Would prompt about untracked files" -ForegroundColor Gray
        }
    }
    
    Write-Host "Staging all files for release commit..."
    git add -A  # Add all files (new, modified, deleted)
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Git add failed with exit code $LASTEXITCODE"
        Write-Error "Cannot stage files for commit."
        exit 1
    }
    
    # Show what's being staged
    Write-Host "`nFiles staged for commit:" -ForegroundColor Green
    $stagedFiles = git diff --cached --name-status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to get staged files: $stagedFiles"
        exit 1
    }
    
    $stagedFiles | ForEach-Object {
        if ($_) {
            $parts = $_ -split '\t'
            if ($parts.Count -ge 2) {
                $status = switch ($parts[0]) {
                    'A' { 'Added' }
                    'M' { 'Modified' }
                    'D' { 'Deleted' }
                    'R' { 'Renamed' }
                    default { $parts[0] }
                }
                Write-Host "  [$status] $($parts[1])"
            }
        }
    }
    
    # Note: MSI file is NOT added to Git (handled by .gitignore)

    # Check if we need to create a fresh commit (after soft reset) or amend
    if ($script:CreateFreshCommit) {
        Write-Host "Creating single release commit with all changes..." -ForegroundColor Green
        git commit -m $commitMessage
    } else {
        Write-Host "Committing release files with message: '$commitMessage'..."
        git commit -m $commitMessage
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Git commit failed with exit code $LASTEXITCODE"
        Write-Error "Cannot create release commit."
        exit 1
    }
    
    # Capture the commit hash for the release
    $releaseCommitHash = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($releaseCommitHash)) {
        Write-Error "Failed to get commit hash"
        exit 1
    }
    Write-Host "Release commit hash: $releaseCommitHash"
    
    # Create the tag locally
    Write-Host "Creating local tag: $tagName"
    git tag $tagName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create tag $tagName"
        exit 1
    }
    
    # Save commit state
    Set-ReleaseState -Key "commit_created" -Value "true"
    Set-ReleaseState -Key "commit_hash" -Value $releaseCommitHash
    Set-ReleaseState -Key "tag_created" -Value "true"
    
    if (-not $DryRun) {
        Write-Host "Pushing commit to remote repository..."
        git push
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Git push failed with exit code: $LASTEXITCODE"
            Write-Error "You may need to run: git push --set-upstream origin <current-branch>"
            exit 1
        }
        Write-Host "Git push successful (commit)." -ForegroundColor Green
        Set-ReleaseState -Key "commit_pushed" -Value "true"
        
        # Push tag separately to ensure it's available for release creation
        Write-Host "Pushing tag $tagName to remote repository..."
        git push origin $tagName
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Tag push failed with exit code: $LASTEXITCODE"
            exit 1
        }
        Write-Host "Tag push successful." -ForegroundColor Green
        Set-ReleaseState -Key "tag_pushed" -Value "true"
    }
    } # End of commit creation if/else block
    
    # --- GitHub Release Creation (runs regardless of resume state) ---
    if (-not $DryRun) {
        Write-Host "---"
        
        # Check if release already exists
        if ($script:IsResuming -and $script:ResumeState.ContainsKey("release_created") -and $script:ResumeState.release_created -eq "true") {
            Write-Host "GitHub release was already created in previous run..." -ForegroundColor Green
            
            # Check if asset was uploaded
            if (-not $script:ResumeState.ContainsKey("asset_uploaded") -or $script:ResumeState.asset_uploaded -ne "true") {
                Write-Host "MSI asset not yet uploaded, uploading now..." -ForegroundColor Yellow
                Write-Host "Uploading '$msiFileName' from '$msiFilePath' to GitHub Release '$tagName'..."
                gh release upload $tagName $msiFilePath --clobber
                if ($LASTEXITCODE -eq 0) {
                    Set-ReleaseState -Key "asset_uploaded" -Value "true"
                    Write-Host "Asset upload successful." -ForegroundColor Green
                } else {
                    Write-Error "Asset upload failed with exit code: $LASTEXITCODE"
                    exit 1
                }
            }
        } else {
            Write-Host "Attempting GitHub Release creation and asset upload..."
            $releaseTitle = "Release $tagName"
            Write-Host "Creating GitHub tag '$tagName' and release '$releaseTitle'..."
        
        # Extract changelog notes for the release body
        $changelogPathForNotesExtraction = Join-Path -Path $PSScriptRoot -ChildPath "CHANGELOG.md"
        Write-Host "DEBUG: Changelog path for notes extraction: $changelogPathForNotesExtraction"

        $getNotesParams = @{
            Version = $ScriptVersion
            ChangelogFilePath = $changelogPathForNotesExtraction # Pass path instead of lines
        }
        Write-Host "DEBUG: Splatting parameters for Get-ChangelogNotesForVersion:"
        $getNotesParams.GetEnumerator() | ForEach-Object { Write-Host "DEBUG:   $($_.Key) = '$($_.Value)' (Type: $($_.Value.GetType().FullName))" }
        
        $releaseNotesBody = Get-ChangelogNotesForVersion @getNotesParams
        
        # Use release notes as-is (no commit link needed with single-push approach)
        $enhancedReleaseNotes = if ([string]::IsNullOrWhiteSpace($releaseNotesBody)) {
            "Automated release of version $ScriptVersion. See CHANGELOG.md for details."
        } else {
            $releaseNotesBody
        }
        
        $tempNotesFilePath = Join-Path -Path $PSScriptRoot -ChildPath "temp_release_notes.md" # Or use $env:TEMP

        if ([string]::IsNullOrWhiteSpace($releaseNotesBody)) {
            Write-Warning "Could not extract changelog notes for version $ScriptVersion from CHANGELOG.md. Using default notes string."
            gh release create $tagName --title $releaseTitle --notes $enhancedReleaseNotes 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Failed to create GitHub release"
                exit 1
            }
        } else {
            Write-Host "Successfully extracted changelog notes for version $ScriptVersion. Writing to temporary file for release body."
            try {
                Set-Content -Path $tempNotesFilePath -Value $enhancedReleaseNotes -Encoding UTF8
                Write-Host "DEBUG: Notes written to $tempNotesFilePath"
                gh release create $tagName --title $releaseTitle --notes-file $tempNotesFilePath 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) {
                    throw "Failed to create GitHub release with notes file"
                }
            } catch {
                Write-Error "Error during GitHub release creation with notes file: $($_.Exception.Message)"
                # Fallback to enhanced notes if file method fails for some reason
                Write-Warning "Falling back to enhanced notes string due to error with notes file."
                gh release create $tagName --title $releaseTitle --notes "$enhancedReleaseNotes (Error using notes file)" 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Failed to create GitHub release even with fallback method"
                    exit 1
                }
            } finally {
                if (Test-Path $tempNotesFilePath) {
                    Write-Host "DEBUG: Removing temporary notes file: $tempNotesFilePath"
                    Remove-Item $tempNotesFilePath -Force
                }
            }
        }
        
        # Save release created state
        Set-ReleaseState -Key "release_created" -Value "true"
        
        Write-Host "Uploading '$msiFileName' from '$msiFilePath' to GitHub Release '$tagName'..."
        gh release upload $tagName $msiFilePath --clobber 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to upload MSI to GitHub release"
            exit 1
        }
        Write-Host "Asset upload successful."
        Set-ReleaseState -Key "asset_uploaded" -Value "true"
        } # End of release creation block
        
        Write-Host "All Git and GitHub operations completed successfully."
        
        # Clean up state file on successful completion
        Clear-ReleaseState
        Write-Host "Release state cleared." -ForegroundColor Green
    } else {
        Write-Host "DRY RUN: Skipping git push, GitHub release creation, and asset upload."
        Write-Host "DRY RUN: Installer manifest already contains the correct URL: https://github.com/$script:PublisherName/$script:PackageName/releases/download/$tagName/$msiFileName"
    }
} catch {
    Write-Warning "An error occurred during Git or GitHub CLI operations: $($_.Exception.Message)"
    Write-Warning "Please review the Git status and GitHub releases, then perform any remaining steps manually."
}

# --- Rotate Local Archives ---
Limit-LocalReleaseArchives -ArchiveDirectory $releasesArchiveDir -KeepCount 10

# --- Winget Submission Preparation ---
if ($SubmitToWinget.IsPresent) {
    Write-Host "---"
    Write-Host "---"
    Write-Host "Preparing for Winget submission..."
    $wingetPkgsManifestTargetDir = Join-Path -Path $WingetPkgsRepoPath -ChildPath "manifests\$($script:PublisherName.Substring(0,1).ToLower())\$script:PublisherName\$script:PackageName"
    
    Write-Host "Ensuring target directory exists in winget-pkgs clone: $wingetPkgsManifestTargetDir"
        New-Item -ItemType Directory -Path $wingetPkgsManifestTargetDir -Force | Out-Null

    Write-Host "Copying manifests to $wingetPkgsManifestTargetDir..."
    Copy-Item -Path $versionManifestPath -Destination $wingetPkgsManifestTargetDir -Force
    Copy-Item -Path $localeManifestPath -Destination $wingetPkgsManifestTargetDir -Force
    Copy-Item -Path $installerManifestPath -Destination $wingetPkgsManifestTargetDir -Force
    Write-Host "Manifests copied."

    Write-Host "Validating manifests in winget-pkgs clone path..."
    try {
        winget validate --manifests $wingetPkgsManifestTargetDir
        Write-Host "Winget validation successful (or warnings issued)."
    } catch {
        Write-Warning "Winget validation failed. Please check the output above. Error: $($_.Exception.Message)"
    }

    if (-not $DryRun) {
        Write-Host "Preparing commit in local winget-pkgs repository at '$WingetPkgsRepoPath'..."
        $currentLocation = Get-Location
        Set-Location -Path $WingetPkgsRepoPath
        
        Write-Host "Staging manifests in winget-pkgs repository..."
        $relativeManifestPathForWingetPkgs = "manifests\$($script:PublisherName.Substring(0,1).ToLower())\$script:PublisherName\$script:PackageName"
        git add $relativeManifestPathForWingetPkgs 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to stage manifests in winget-pkgs repository"
            Set-Location -Path $currentLocation
            exit 1
        }
        
        $commitMessageWinget = "Add $PackageIdentifier v$ScriptVersion"
        Write-Host "Committing manifests in winget-pkgs repository with message: '$commitMessageWinget'..."
        git commit -m $commitMessageWinget 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to commit manifests in winget-pkgs repository"
            Set-Location -Path $currentLocation
            exit 1
        }
        
        Set-Location -Path $currentLocation
        Write-Host "Commit prepared in '$WingetPkgsRepoPath'."
        Write-Host "NEXT STEPS for Winget Submission:"
        Write-Host "1. Navigate to '$WingetPkgsRepoPath'."
        Write-Host "2. Manually run 'git push' to push the commit to your fork."
        Write-Host "3. Create a Pull Request from your fork to 'microsoft/winget-pkgs' on GitHub."
    } else {
        Write-Host "DRY RUN: Skipping commit preparation in local winget-pkgs repository."
        Write-Host "DRY RUN: Manifests would be copied to '$wingetPkgsManifestTargetDir' and validated."
    }
}

Write-Host "---"
Write-Host ""
if ($DryRun) {
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "     DRY RUN COMPLETED SUCCESSFULLY! " -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Release v$ScriptVersion is ready to publish." -ForegroundColor Cyan
    Write-Host "MSI installer created: $msiFileName" -ForegroundColor Cyan
    Write-Host "SHA256: $fileHash" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To create the actual release, run without -DryRun:" -ForegroundColor Yellow
    Write-Host "  .\publish_new_release.ps1 -PackageIdentifier '$PackageIdentifier'" -ForegroundColor White
} else {
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "     RELEASE v$ScriptVersion PUBLISHED! " -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ MSI installer created: $msiFileName" -ForegroundColor Green
    Write-Host "✓ GitHub release created with tag: $tagName" -ForegroundColor Green
    Write-Host "✓ Manifests updated with download URL" -ForegroundColor Green
    Write-Host "✓ All changes committed and pushed" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Verify the release: https://github.com/$script:PublisherName/$script:PackageName/releases/tag/$tagName" -ForegroundColor White
    Write-Host "2. Test the MSI download link" -ForegroundColor White
    if ($SubmitToWinget) {
        Write-Host "3. Submit PR to winget-pkgs repository" -ForegroundColor White
    }
}

# --- Version revert removed ---
# Dry runs will now keep the incremented version to avoid duplicate installations
# when testing MSI upgrades with the same version number