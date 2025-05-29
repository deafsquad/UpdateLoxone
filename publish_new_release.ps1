<#
.SYNOPSIS
Automates the process of packaging the UpdateLoxone script and generating winget manifest files.

.DESCRIPTION
This script performs the following actions:
1. Automatically determines the current version from existing winget manifests or defaults to 0.0.0.
2. Bumps the version (patch, then minor, then major, with rollover at .9 for patch/minor).
3. Takes publisher name as input.
4. Automatically determines author name from existing locale manifest or defaults to publisher name.
5. Packages the necessary files (UpdateLoxone.ps1, LoxoneUtils/, assets, README, CHANGELOG) into a ZIP archive named with the new version.
6. Calculates the SHA256 hash of the ZIP archive.
7. Generates a multi-file winget manifest for the new version in the './manifests' directory.
8. Checks if CHANGELOG.md contains an entry for the new version; exits if not.
9. Stages README.md, CHANGELOG.md, the new ZIP archive, and the new manifest files using Git.
10. Commits the staged files with a message "Release vX.Y.Z".
11. Attempts to push the commit to the remote repository.

.PARAMETER PublisherName
(Required) The publisher name (e.g., your GitHub username).

.PARAMETER PackageIdentifier
(Optional) The winget package identifier. Defaults to "$PublisherName.UpdateLoxone".

.PARAMETER PackageName
(Optional) The winget package name. Defaults to "UpdateLoxone".

.EXAMPLE
.\publish_new_release.ps1 -PublisherName "deafsquad"

.IMPORTANT
BEFORE RUNNING THIS SCRIPT:
1. Manually update 'CHANGELOG.md' to include a section for the new version that will be generated (e.g., "## [X.Y.Z] - YYYY-MM-DD"). The script will verify this.
2. Manually update 'README.md' if there are any changes to usage, features, etc.
3. Ensure you are in the root of your Git repository.
4. Ensure Git is installed and configured (including credentials for push).
5. Ensure your working directory is clean or changes are committed/stashed.

.NOTES
The script will attempt to stage, commit, and push the new ZIP archive and manifest files.
If the Git push fails, you may need to push manually.
The 'InstallerUrl' in the generated installer manifest still needs to be updated with the
actual public URL of the ZIP file AFTER it has been uploaded (e.g., via GitHub Releases).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$PublisherName,

    [string]$PackageIdentifier = "$($PublisherName).UpdateLoxone",

    [string]$PackageName = "UpdateLoxone"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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
            # If the loop completes without returning, it means the version line wasn't found
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
function Increment-Version {
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
        [string]$LocaleManifestPath, # Path to the locale manifest (e.g., deafsquad.UpdateLoxone.locale.en-US.yaml)
        [string]$DefaultAuthor       # Fallback author name (usually PublisherName)
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

# --- Determine Manifest Paths (needed early for version and author detection) ---
$manifestDir = Join-Path -Path $PSScriptRoot -ChildPath "manifests"
$publisherSubDir = Join-Path -Path $manifestDir -ChildPath $PublisherName.Substring(0,1).ToLower()
$packageSubDir = Join-Path -Path $publisherSubDir -ChildPath $PublisherName
$finalManifestDir = Join-Path -Path $packageSubDir -ChildPath $PackageName
$versionManifestPathForVersionDetection = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.yaml"
$localeManifestPathForAuthorDetection = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.locale.en-US.yaml"

# --- Determine and Bump Version ---
$currentVersion = Get-CurrentVersion -BaseManifestPath $versionManifestPathForVersionDetection
$ScriptVersion = Increment-Version -CurrentVersionString $currentVersion

# --- Determine Author Name ---
$AuthorName = Get-CurrentAuthor -LocaleManifestPath $localeManifestPathForAuthorDetection -DefaultAuthor $PublisherName

Write-Host "Starting release process for $PackageName version $ScriptVersion (Author: $AuthorName)..."

# --- Pre-flight checks ---
# Check CHANGELOG.md for the new version entry
$changelogPath = Join-Path -Path $PSScriptRoot -ChildPath "CHANGELOG.md"
if (-not (Test-Path $changelogPath)) {
    Write-Error "CHANGELOG.md not found at $changelogPath."
    exit 1
}
$changelogContent = Get-Content $changelogPath -Raw # Read all content for easier matching
# Ensure the version string is properly escaped for regex, especially the dots.
$escapedVersionForRegex = [regex]::Escape($ScriptVersion)
$versionHeaderPattern = "## \[$escapedVersionForRegex\]" # Regex: ## [X.Y.Z]

if ($changelogContent -notmatch $versionHeaderPattern) {
    Write-Error "CHANGELOG.md does not contain an entry for the new version $ScriptVersion."
    Write-Error "Please add a section like '## [$ScriptVersion] - $(Get-Date -Format 'yyyy-MM-dd')' to CHANGELOG.md and try again."
    exit 1
}
Write-Host "CHANGELOG.md contains an entry for version $ScriptVersion."

$requiredFiles = @(
    ".\UpdateLoxone.ps1",
    ".\LoxoneUtils\LoxoneUtils.psd1", # Check for a key file in LoxoneUtils
    ".\ms.png",
    ".\nok.png",
    ".\ok.png",
    ".\UpdateLoxoneMSList.txt.example",
    ".\Send-GoogleChat.ps1",
    ".\README.md",
    ".\CHANGELOG.md" # Already checked for content, but ensure it's in the list for other checks if any
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        Write-Error "Required file not found: $file. Please ensure all necessary files are present."
        exit 1 # Should not happen for CHANGELOG.md due to check above, but good for others
    }
}
Write-Host "All required files seem to be present."
Write-Host "IMPORTANT: Ensure you have manually updated README.md if necessary for version $ScriptVersion."
# Read-Host prompt removed, CHANGELOG check is now automated.

# --- Define files and directories ---
$zipFileName = "UpdateLoxone-v$ScriptVersion.zip"
$zipFilePath = Join-Path -Path $PSScriptRoot -ChildPath $zipFileName

$filesToZip = @(
    ".\UpdateLoxone.ps1",
    ".\LoxoneUtils",
    ".\ms.png",
    ".\nok.png",
    ".\ok.png",
    ".\UpdateLoxoneMSList.txt.example",
    ".\Send-GoogleChat.ps1",
    ".\README.md",
    ".\CHANGELOG.md"
)

# --- Create ZIP Archive ---
Write-Host "Creating ZIP archive: $zipFilePath..."
try {
    Compress-Archive -Path $filesToZip -DestinationPath $zipFilePath -Force
    Write-Host "Successfully created ZIP archive: $zipFilePath"
} catch {
    Write-Error "Failed to create ZIP archive. Error: $($_.Exception.Message)"
    exit 1
}

# --- Calculate SHA256 Hash ---
Write-Host "Calculating SHA256 hash for $zipFilePath..."
$fileHash = Get-FileHash -Path $zipFilePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
Write-Host "SHA256 Hash: $fileHash"

# --- Create Manifests ---
# $manifestDir, $publisherSubDir, $packageSubDir, $finalManifestDir are already defined from earlier
$versionManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.yaml"
$localeManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.locale.en-US.yaml"
$installerManifestPath = Join-Path -Path $finalManifestDir -ChildPath "$PackageIdentifier.installer.yaml"

$currentDate = Get-Date -Format "yyyy-MM-dd"

# Version Manifest
Write-Host "Creating Version manifest: $versionManifestPath..."
$versionManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"@
Set-Content -Path $versionManifestPath -Value $versionManifestContent -Encoding UTF8

# Locale Manifest
Write-Host "Creating Locale manifest: $localeManifestPath..."
$localeManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
PackageLocale: en-US
Publisher: $PublisherName
Author: $AuthorName
PackageName: $PackageName
PackageUrl: https://github.com/$PublisherName/UpdateLoxone # Assuming GitHub, adjust if needed
License: MIT # Assuming MIT, adjust if needed
LicenseUrl: https://github.com/$PublisherName/UpdateLoxone/blob/main/LICENSE # Assuming, adjust
ShortDescription: Automatically checks for Loxone Config updates, downloads, installs them, and updates Miniservers.
Moniker: updateloxone
Tags:
  - loxone
  - automation
  - update
  - smart-home
ManifestType: locale
ManifestVersion: 1.6.0
"@
Set-Content -Path $localeManifestPath -Value $localeManifestContent -Encoding UTF8

# Installer Manifest
Write-Host "Creating Installer manifest: $installerManifestPath..."
$installerManifestContent = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $ScriptVersion
InstallerLocale: en-US
InstallerType: zip
NestedInstallerType: portable # The PS1 script is portable
NestedInstallerFiles:
  - RelativeFilePath: UpdateLoxone.ps1
    PortableCommandAlias: UpdateLoxone.ps1 # Or a more user-friendly alias if you create one
Installers:
  - Architecture: x64 # Assuming x64, adjust if needed for other architectures
    InstallerUrl: REPLACE_WITH_PUBLIC_URL_TO/$zipFileName
    InstallerSha256: $fileHash
ManifestType: installer
ManifestVersion: 1.6.0
"@
Set-Content -Path $installerManifestPath -Value $installerManifestContent -Encoding UTF8

Write-Host "Winget manifests created in: $finalManifestDir"

# --- Git Operations ---
Write-Host "---"
Write-Host "Attempting Git operations..."

# Check if git command is available
try {
    Get-Command git -ErrorAction Stop | Out-Null
    Write-Host "Git command found."
}
catch {
    Write-Warning "Git command not found. Skipping Git operations. Please commit and push manually."
    Write-Host "---"
    Write-Host "Release process for $PackageName v$ScriptVersion (excluding Git) completed."
    Write-Host "ACTION REQUIRED: Upload '$zipFileName' to a public URL and update '$($installerManifestPath.Replace($PSScriptRoot, '.'))' with this URL."
    Write-Host "Example public URL: https://github.com/$PublisherName/UpdateLoxone/releases/download/v$ScriptVersion/$zipFileName"
    exit 0 # Exit successfully as core tasks are done
}

$commitMessage = "Release v$ScriptVersion"
# $manifestRelativePath is not used for git add anymore, individual paths are used.
$zipFileRelativePath = $zipFilePath.Replace($PSScriptRoot, ".")     # Get relative path for git add
$readmeRelativePath = ".\README.md"
$changelogRelativePath = ".\CHANGELOG.md"

try {
    Write-Host "Staging files for commit..."
    Write-Host "Staging README.md: $readmeRelativePath"
    git add -f $readmeRelativePath
    Write-Host "Staging CHANGELOG.md: $changelogRelativePath"
    git add -f $changelogRelativePath
    Write-Host "Staging Version Manifest: $($versionManifestPath.Replace($PSScriptRoot, '.'))"
    git add -f $versionManifestPath # Use full path and force
    Write-Host "Staging Locale Manifest: $($localeManifestPath.Replace($PSScriptRoot, '.'))"
    git add -f $localeManifestPath # Use full path and force
    Write-Host "Staging Installer Manifest: $($installerManifestPath.Replace($PSScriptRoot, '.'))"
    git add -f $installerManifestPath # Use full path and force
    Write-Host "Staging ZIP archive: $zipFileRelativePath"
    git add -f $zipFileRelativePath

    Write-Host "Committing files with message: '$commitMessage'..."
    git commit -m $commitMessage
    Write-Host "Pushing commit to remote repository..."
    git push

    Write-Host "Git operations completed successfully."
}
catch {
    Write-Warning "An error occurred during Git operations: $($_.Exception.Message)"
    Write-Warning "Please review the Git status, commit, and push manually if needed."
    # Optionally, you might want to exit with an error code or specific message here
}

Write-Host "---"
Write-Host "Release process for $PackageName v$ScriptVersion completed."
Write-Host "ACTION REQUIRED: If Git push was successful, create a release/tag on GitHub (or your Git host)."
Write-Host "Then, upload '$zipFileName' to that release and update '$($installerManifestPath.Replace($PSScriptRoot, '.'))' with the final public URL."
Write-Host "If you haven't already, commit and push the updated installer manifest."
Write-Host "Example public URL (after creating GitHub release): https://github.com/$PublisherName/UpdateLoxone/releases/download/v$ScriptVersion/$zipFileName"