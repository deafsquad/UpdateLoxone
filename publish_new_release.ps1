<#
.SYNOPSIS
Automates the process of packaging the UpdateLoxone script and generating winget manifest files.

.DESCRIPTION
This script performs the following actions:
1. Automatically determines the current version from existing winget manifests or defaults to 0.0.0.
2. Bumps the version (patch, then minor, then major, with rollover at .9 for patch/minor).
3. Takes publisher name as input.
4. Automatically determines author name from existing locale manifest or defaults to publisher name.
5. Packages the necessary files into a ZIP archive, storing it locally in './releases_archive/'.
6. Calculates the SHA256 hash of the ZIP archive.
7. Generates a multi-file winget manifest for the new version in the './manifests' directory.
8. Checks if CHANGELOG.md contains an entry for the new version; exits if not.
9. Stages README.md, CHANGELOG.md, and the new manifest files using Git (ZIPs are not committed).
10. Commits the staged files with a message "Release vX.Y.Z".
11. Pushes the commit to the remote repository.
12. Creates a GitHub Tag and Release using 'gh' CLI.
13. Uploads the locally created ZIP as an asset to the GitHub Release.
14. Updates the local installer manifest with the public URL of the uploaded asset.
15. Commits and pushes the updated installer manifest.
16. Rotates local ZIP archives in './releases_archive/', keeping the latest 10.

.PARAMETER PackageIdentifier
(Required) The winget package identifier (e.g., YourGitHubUser.UpdateLoxone).

.PARAMETER DryRun
(Optional) If specified, the script will simulate most operations without making remote changes (no git push, no GitHub release creation/upload).

.PARAMETER WingetPkgsRepoPath
(Optional) The local file path to your cloned fork of the 'winget-pkgs' repository. Required if using -SubmitToWinget.

.PARAMETER SubmitToWinget
(Optional) If specified along with -WingetPkgsRepoPath, the script will copy manifests to your local 'winget-pkgs' clone, run 'winget validate', and prepare a local commit.

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
Local ZIP archives are stored in './releases_archive/' and rotated (default: keep 10).
ZIP files themselves are NOT committed to the Git repository; they are uploaded to GitHub Releases.
#>
[CmdletBinding()]
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)] # Changed from $true
    [string]$PackageIdentifier, # Example: YourGitHubUser.UpdateLoxone. If not provided, script will attempt to auto-discover.

    [switch]$DryRun,
    [string]$WingetPkgsRepoPath,

    [switch]$SubmitToWinget
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
        [string[]]$AllChangelogLines
    )

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
    $archives = @(Get-ChildItem -Path $ArchiveDirectory -Filter "UpdateLoxone-v*.zip" | Sort-Object -Property Name -Descending)
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

# --- Pre-flight checks ---
$changelogPath = Join-Path -Path $PSScriptRoot -ChildPath "CHANGELOG.md"
if (-not (Test-Path $changelogPath)) {
    Write-Error "CHANGELOG.md not found at $changelogPath."
    exit 1
}
$changelogContent = Get-Content $changelogPath -Raw
$escapedVersionForRegex = [regex]::Escape($ScriptVersion)
# Pattern to find the version header, allowing for a date placeholder
$versionHeaderSearchPattern = "## \[$escapedVersionForRegex\]\s*-\s*YYYY-MM-DD_TIMESTAMP_PLACEHOLDER"
$versionHeaderExactPattern = "## \[$escapedVersionForRegex\]" # Used if placeholder not found initially

if ($changelogContent -match $versionHeaderSearchPattern) {
    Write-Host "CHANGELOG.md contains an entry for version $ScriptVersion with date placeholder."
    $currentDateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $lineToReplace = $matches[0] # The whole matched line, e.g., "## [0.1.1] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER"
    $newLine = "## [$ScriptVersion] - $currentDateTime"
    
    # Read content as array for easier line replacement, then write back
    $changelogLines = Get-Content $changelogPath
    for ($i = 0; $i -lt $changelogLines.Length; $i++) {
        if ($changelogLines[$i] -eq $lineToReplace) {
            $changelogLines[$i] = $newLine
            Write-Host "Updated date in CHANGELOG.md for version $ScriptVersion to $currentDateTime."
            break
        }
    }
    Set-Content -Path $changelogPath -Value $changelogLines
    # Re-read content to ensure subsequent git add picks up the change
    $changelogContent = Get-Content $changelogPath -Raw

} elseif ($changelogContent -notmatch $versionHeaderExactPattern) {
    # If neither placeholder nor a simple header is found
    Write-Error "CHANGELOG.md does not contain an entry for the new version $ScriptVersion."
    Write-Error "Please add a section like '## [$ScriptVersion] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER' to CHANGELOG.md and try again."
    exit 1
} else {
    # Header found, but no placeholder - assume date is already set or manually managed for this run
    Write-Host "CHANGELOG.md contains an entry for version $ScriptVersion (date assumed manually set or pre-existing)."
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
$releasesArchiveDirName = "releases_archive"
$releasesArchiveDir = Join-Path -Path $PSScriptRoot -ChildPath $releasesArchiveDirName
if (-not (Test-Path $releasesArchiveDir)) {
    Write-Host "Creating local releases archive directory: $releasesArchiveDir"
    New-Item -ItemType Directory -Path $releasesArchiveDir | Out-Null
}
$zipFileName = "UpdateLoxone-v$ScriptVersion.zip"
$zipFilePath = Join-Path -Path $releasesArchiveDir -ChildPath $zipFileName

# --- Create ZIP Archive ---
$filesToZip = @(
    ".\UpdateLoxone.ps1", ".\LoxoneUtils", ".\ms.png", ".\nok.png", ".\ok.png",
    ".\UpdateLoxoneMSList.txt.example", ".\Send-GoogleChat.ps1", ".\README.md", ".\CHANGELOG.md"
)
Write-Host "Creating ZIP archive: $zipFilePath..."
Compress-Archive -Path $filesToZip -DestinationPath $zipFilePath -Force
Write-Host "Successfully created ZIP archive: $zipFilePath"

# --- Calculate SHA256 Hash ---
Write-Host "Calculating SHA256 hash for $zipFilePath..."
$fileHash = Get-FileHash -Path $zipFilePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
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
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: UpdateLoxone.ps1
    PortableCommandAlias: UpdateLoxone.ps1
Installers:
  - Architecture: x64
    InstallerUrl: REPLACE_WITH_PUBLIC_URL_TO/$zipFileName 
    InstallerSha256: $fileHash
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
    Write-Host "Staging files for initial commit (scripts, manifests, docs)..."
    git add -f (Join-Path -Path $PSScriptRoot -ChildPath "UpdateLoxone.ps1")
    git add -f (Join-Path -Path $PSScriptRoot -ChildPath "LoxoneUtils") # Stage the whole LoxoneUtils directory
    git add -f $MyInvocation.MyCommand.Path # Stage the publish_new_release.ps1 script itself
    git add -f $readmeRelativePath
    git add -f $changelogRelativePath
    git add -f $versionManifestPath
    git add -f $localeManifestPath
    git add -f $installerManifestPath
    # Note: ZIP file is NOT added to Git

    Write-Host "Committing initial release files with message: '$commitMessage'..."
    Write-Host "Committing initial release files with message: '$commitMessage'..."
    git commit -m $commitMessage
    
    if (-not $DryRun) {
        Write-Host "Pushing initial commit to remote repository..."
        git push
        Write-Host "Initial Git push successful."
        Write-Host "---"

        Write-Host "Attempting GitHub Release creation and asset upload..."
        $releaseTitle = "Release $tagName"
        Write-Host "Creating GitHub tag '$tagName' and release '$releaseTitle'..."
        
        # Extract changelog notes for the release body
        $changelogPathForNotesExtraction = Join-Path -Path $PSScriptRoot -ChildPath "CHANGELOG.md"
        $changelogLinesForNotes = @(Get-Content $changelogPathForNotesExtraction)
        $releaseNotesBody = Get-ChangelogNotesForVersion -Version $ScriptVersion -AllChangelogLines $changelogLinesForNotes
        
        if ([string]::IsNullOrWhiteSpace($releaseNotesBody)) {
            Write-Warning "Could not extract changelog notes for version $ScriptVersion from CHANGELOG.md. Using default notes."
            $releaseNotesBody = "Automated release of version $ScriptVersion. See CHANGELOG.md for details."
        } else {
            Write-Host "Successfully extracted changelog notes for version $ScriptVersion to be used in the release body."
        }

        gh release create $tagName --title $releaseTitle --notes $releaseNotesBody
        
        Write-Host "Uploading '$zipFileName' from '$zipFilePath' to GitHub Release '$tagName'..."
        gh release upload $tagName $zipFilePath --clobber
        Write-Host "Asset upload successful."

        $InstallerUrl = "https://github.com/$script:PublisherName/$script:PackageName/releases/download/$tagName/$zipFileName"
        Write-Host "Constructed InstallerUrl: $InstallerUrl"

        Write-Host "Updating installer manifest '$installerManifestRelativePath' with new URL..."
        $installerContent = Get-Content $installerManifestPath -Raw
        $placeholderUrl = "REPLACE_WITH_PUBLIC_URL_TO/$zipFileName"
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
        Write-Host "All Git and GitHub operations completed successfully."
    } else {
            Write-Host "DRY RUN: Skipping git push, GitHub release creation, asset upload, and installer URL update commit/push."
            Write-Host "DRY RUN: InstallerUrl would be: https://github.com/$script:PublisherName/$script:PackageName/releases/download/$tagName/$zipFileName"
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
Write-Host "Release process for $script:PackageName v$ScriptVersion completed."
if (-not $DryRun) {
    Write-Host "Please verify the GitHub release, tag, and asset: https://github.com/$script:PublisherName/$script:PackageName/releases/tag/$tagName"
    Write-Host "Verify the installer manifest URL has been updated in your repository."
}