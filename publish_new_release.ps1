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

# --- Function to Extract Changelog Notes for a Specific Version ---
function Get-ChangelogNotesForVersion {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Version,

        [Parameter(Mandatory=$true)]
        [string]$ChangelogFilePath # Changed from AllChangelogLines
    )

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
    $versionHeaderPattern = "^## \[$escapedVersion\]" # Pattern for the start of the target version's header
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
                    $parsedVersion = $matches[1]
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
$currentVersion = Get-CurrentVersion -BaseManifestPath $versionManifestPathForVersionDetection
$ScriptVersion = Get-NextVersion -CurrentVersionString $currentVersion

# --- Determine Author Name ---
$AuthorName = Get-CurrentAuthor -LocaleManifestPath $localeManifestPathForAuthorDetection -DefaultAuthor $script:PublisherName

Write-Host "Starting release process for $script:PackageName version $ScriptVersion (Author: $AuthorName)..."

# --- Run Tests First ---
if ($SkipTests) {
    Write-Warning "SKIPPING TESTS - This is not recommended for production releases!"
    Write-Host ""
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
    
    # Run the test script - use sequential runs to avoid the "All" test type issues
    Write-Host "Running tests sequentially to avoid context issues..." -ForegroundColor Cyan
    
    $testExitCode = 0
    $testOutput = @()
    
    # Run each test type separately
    $testTypes = @('Unit', 'Integration', 'System')
    
    foreach ($testType in $testTypes) {
        Write-Host "Running $testType tests..." -ForegroundColor Cyan
        
        try {
            # Run test type and capture exit code
            & $testScriptPath -TestType $testType -CI -LogToFile
            
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "$testType tests failed with exit code: $LASTEXITCODE"
                $testExitCode = $LASTEXITCODE
                break
            }
        } catch {
            Write-Error "Error running $testType tests: $_"
            $testExitCode = 1
            break
        }
    }
    
    # If all test types passed, run coverage analysis
    if ($testExitCode -eq 0) {
        Write-Host "All tests passed. Running coverage analysis..." -ForegroundColor Green
        try {
            & $testScriptPath -TestType Unit -Coverage -CI -LogToFile
        } catch {
            Write-Warning "Coverage analysis failed but tests passed: $_"
        }
    }
    
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
$currentDateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$changelogLines = Get-Content $changelogPath
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
$changelogContent = Get-Content $changelogPath -Raw
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
    Write-Error "CHANGELOG.md does not contain a valid entry for the new version $ScriptVersion after attempting updates."
    Write-Error "Please ensure an '## [Unreleased] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER' section is at the top, or a specific '## [$ScriptVersion] ...' entry exists."
    exit 1
} else {
    # An entry for $ScriptVersion exists.
    if ($changelogUpdatedByScript) {
         Write-Host "CHANGELOG.md successfully prepared by script for version $ScriptVersion."
    } else {
        # This means an entry for $ScriptVersion was already present with a specific date (not the placeholder).
        Write-Host "CHANGELOG.md already contained a dated entry for version $ScriptVersion."
    }
}


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
    $actualMsiPath = Join-Path $releasesArchiveDir "$script:PackageName.$ScriptVersion.x86.msi"
    
    # Rename to our expected filename
    if (Test-Path $actualMsiPath) {
        Move-Item -Path $actualMsiPath -Destination $msiFilePath -Force
        Write-Host "Successfully created MSI installer: $msiFilePath"
    } else {
        # Check for x64 version
        $actualMsiPath = Join-Path $releasesArchiveDir "$script:PackageName.$ScriptVersion.x64.msi"
        if (Test-Path $actualMsiPath) {
            Move-Item -Path $actualMsiPath -Destination $msiFilePath -Force
            Write-Host "Successfully created MSI installer: $msiFilePath"
        } else {
            throw "MSI file not found after creation. Expected pattern: $script:PackageName.$ScriptVersion.*.msi"
        }
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

# --- Create Manifests ---
$versionManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.yaml"
$localeManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.locale.en-US.yaml"
$installerManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.installer.yaml"

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

$installerManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
InstallerLocale: en-US
InstallerType: msi
Installers:
  - Architecture: x64
    InstallerUrl: REPLACE_WITH_PUBLIC_URL_TO/$msiFileName 
    InstallerSha256: $fileHash
    ProductCode: '{00000000-0000-0000-0000-000000000000}'
ManifestType: installer
ManifestVersion: 1.6.0
"@
Set-Content -Path $installerManifestPath -Value $installerManifestContent -Encoding UTF8
Write-Host "Winget manifests created in: $finalManifestDir"

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

try {
    # Check for untracked files first
    Write-Host "Checking for untracked files..."
    $untrackedFiles = git ls-files --others --exclude-standard
    
    if ($untrackedFiles) {
        Write-Host "`nThe following untracked files were found:" -ForegroundColor Yellow
        $untrackedFiles | ForEach-Object { Write-Host "  - $_" }
        
        if (-not $DryRun) {
            Write-Host "`nDo you want to include these files in the release? (Y/N)" -ForegroundColor Cyan
            $response = Read-Host
            
            if ($response -ne 'Y' -and $response -ne 'y') {
                Write-Host "Aborting release. Please handle untracked files manually:" -ForegroundColor Yellow
                Write-Host "  - Add them to .gitignore if they should be ignored"
                Write-Host "  - Delete them if they're temporary files"
                Write-Host "  - Commit them separately if they're needed but not for this release"
                exit 1
            }
        } else {
            Write-Host "DRY RUN: Would prompt about untracked files" -ForegroundColor Gray
        }
    }
    
    Write-Host "Staging all files for release commit..."
    git add -A  # Add all files (new, modified, deleted)
    
    # Show what's being staged
    Write-Host "`nFiles staged for commit:" -ForegroundColor Green
    git diff --cached --name-status | ForEach-Object {
        $parts = $_ -split '\t'
        $status = switch ($parts[0]) {
            'A' { 'Added' }
            'M' { 'Modified' }
            'D' { 'Deleted' }
            'R' { 'Renamed' }
            default { $parts[0] }
        }
        Write-Host "  [$status] $($parts[1])"
    }
    
    # Note: MSI file is NOT added to Git (handled by .gitignore)

    Write-Host "Committing initial release files with message: '$commitMessage'..."
    Write-Host "Committing initial release files with message: '$commitMessage'..."
    git commit -m $commitMessage
    
    # Capture the commit hash for the release
    $releaseCommitHash = git rev-parse HEAD
    Write-Host "Release commit hash: $releaseCommitHash"
    
    if (-not $DryRun) {
        Write-Host "Pushing initial commit to remote repository..."
        git push
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Git push failed with exit code: $LASTEXITCODE"
            Write-Error "You may need to run: git push --set-upstream origin $(git branch --show-current)"
            exit 1
        }
        Write-Host "Initial Git push successful."
        Write-Host "---"

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
        
        # Add commit link to release notes
        $repoUrl = "https://github.com/$script:PublisherName/$script:PackageName"
        $commitUrl = "$repoUrl/commit/$releaseCommitHash"
        $enhancedReleaseNotes = if ([string]::IsNullOrWhiteSpace($releaseNotesBody)) {
            "Automated release of version $ScriptVersion. See CHANGELOG.md for details.`n`n**Release Commit:** $commitUrl"
        } else {
            "$releaseNotesBody`n`n---`n**Release Commit:** $commitUrl"
        }
        
        $tempNotesFilePath = Join-Path -Path $PSScriptRoot -ChildPath "temp_release_notes.md" # Or use $env:TEMP

        if ([string]::IsNullOrWhiteSpace($releaseNotesBody)) {
            Write-Warning "Could not extract changelog notes for version $ScriptVersion from CHANGELOG.md. Using default notes string."
            gh release create $tagName --title $releaseTitle --notes $enhancedReleaseNotes
        } else {
            Write-Host "Successfully extracted changelog notes for version $ScriptVersion. Writing to temporary file for release body."
            try {
                Set-Content -Path $tempNotesFilePath -Value $enhancedReleaseNotes -Encoding UTF8
                Write-Host "DEBUG: Notes written to $tempNotesFilePath"
                gh release create $tagName --title $releaseTitle --notes-file $tempNotesFilePath
            } catch {
                Write-Error "Error during GitHub release creation with notes file: $($_.Exception.Message)"
                # Fallback to enhanced notes if file method fails for some reason
                Write-Warning "Falling back to enhanced notes string due to error with notes file."
                gh release create $tagName --title $releaseTitle --notes "$enhancedReleaseNotes (Error using notes file)"
            } finally {
                if (Test-Path $tempNotesFilePath) {
                    Write-Host "DEBUG: Removing temporary notes file: $tempNotesFilePath"
                    Remove-Item $tempNotesFilePath -Force
                }
            }
        }
        
        Write-Host "Uploading '$msiFileName' from '$msiFilePath' to GitHub Release '$tagName'..."
        gh release upload $tagName $msiFilePath --clobber
        Write-Host "Asset upload successful."

        $InstallerUrl = "https://github.com/$script:PublisherName/$script:PackageName/releases/download/$tagName/$msiFileName"
        Write-Host "Constructed InstallerUrl: $InstallerUrl"

        Write-Host "Updating installer manifest '$installerManifestRelativePath' with new URL..."
        $installerContent = Get-Content $installerManifestPath -Raw
        $placeholderUrl = "REPLACE_WITH_PUBLIC_URL_TO/$msiFileName"
        $updatedInstallerContent = $installerContent -replace [regex]::Escape($placeholderUrl), $InstallerUrl
        Set-Content -Path $installerManifestPath -Value $updatedInstallerContent -Encoding UTF8
        Write-Host "Installer manifest updated."

        Write-Host "Staging updated installer manifest..."
        git add -f $installerManifestPath
        
        $commitMessageUrlUpdate = "Update installer URL for v$ScriptVersion"
        Write-Host "Committing updated installer manifest with message: '$commitMessageUrlUpdate'..."
        git commit -m $commitMessageUrlUpdate
        
        Write-Host "Pushing updated installer manifest to remote repository..."
        git push
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Git push for installer manifest failed with exit code: $LASTEXITCODE"
            Write-Error "The release was created but the installer manifest update could not be pushed."
            Write-Error "You may need to run: git push --set-upstream origin $(git branch --show-current)"
            exit 1
        }
        Write-Host "All Git and GitHub operations completed successfully."
    } else {
            Write-Host "DRY RUN: Skipping git push, GitHub release creation, asset upload, and installer URL update commit/push."
            Write-Host "DRY RUN: InstallerUrl would be: https://github.com/$script:PublisherName/$script:PackageName/releases/download/$tagName/$msiFileName"
            Write-Host "DRY RUN: Installer manifest at '$installerManifestPath' still contains placeholder URL."
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
        git add $relativeManifestPathForWingetPkgs
        
        $commitMessageWinget = "Add $PackageIdentifier v$ScriptVersion"
        Write-Host "Committing manifests in winget-pkgs repository with message: '$commitMessageWinget'..."
        git commit -m $commitMessageWinget
        
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