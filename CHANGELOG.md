# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.9] - 2025-05-30 02:14:30
### Fixed
- Correctly applied the addition of `-UseBasicParsing` to the HTTP fallback logic within the `Get-MiniserverVersion` function in `LoxoneUtils.Miniserver.psm1`. This was intended for v0.1.8 but was not included due to an error. This change aims to improve compatibility with Gen1 Miniservers that might be sensitive to `Invoke-WebRequest`'s default parsing, potentially resolving persistent 401 errors.
- Corrected syntax errors in `Get-MiniserverVersion` that were introduced during a previous modification attempt.
## [0.1.8] - 2025-05-30 02:05:54
### Fixed
- Added `-UseBasicParsing` to the HTTP fallback in `Get-MiniserverVersion` within `LoxoneUtils.Miniserver.psm1`. This is an attempt to improve compatibility with Gen1 Miniservers that might be sensitive to how `Invoke-WebRequest` handles responses without this parameter, potentially resolving persistent 401 errors.
## [0.1.7] - 2025-05-30 02:03:52
### Changed
- Modified `Get-MiniserverVersion` in `LoxoneUtils.Miniserver.psm1` to manually construct the `Authorization` header for HTTP fallback attempts. This aims to resolve 401 Unauthorized errors with Gen1 Miniservers by ensuring Basic Authentication is handled more explicitly, similar to direct `Invoke-WebRequest` tests that were successful with a manual header.
## [0.1.6] - 2025-05-30 02:00:02
### Changed
- Updated `publish_new_release.ps1` to auto-detect `PackageIdentifier` if not provided.
- Updated `publish_new_release.ps1` to include itself in the files staged for the release commit.
## [0.1.5] - 2025-05-30 01:58:21
### Changed
- Investigated 401 Unauthorized errors for Gen1 Miniservers during version checks.
- Added enhanced debug logging to `Get-MiniserverVersion` in `LoxoneUtils.Miniserver.psm1` to provide more detailed information on credential parsing and `Invoke-WebRequest` parameters for HTTP calls, aiding in diagnosing authentication issues.
## [0.1.4] - 2025-05-30 01:33:10
### Fixed
- Updated `publish_new_release.ps1` to ensure `UpdateLoxone.ps1` and the `LoxoneUtils` directory (including `LoxoneUtils.psd1` and `LoxoneUtils.psm1`) are staged and committed for releases. This ensures fixes for issues like the BurntToast dependency are correctly included in new versions.
## [0.1.3] - 2025-05-30 01:29:46
### Fixed
- Improved `BurntToast` dependency handling:
    - `BurntToast` is now explicitly imported into the session after installation or if found pre-existing, ensuring its availability for `LoxoneUtils`.
    - `BurntToast` was removed from `RequiredModules` in `LoxoneUtils.psd1` to allow the main script to manage its loading.
## [0.1.2] - 2025-05-30 01:23:22
### Fixed
- Ensured `BurntToast` module is installed if missing before attempting to import `LoxoneUtils`, resolving startup errors on new machines.
## [0.1.1] - 2025-05-30 01:11:16
### Changed
- Corrected CHANGELOG.md date placeholder update logic in publish script.
### Added
- This entry for testing the refined date update.

## [0.1.0] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Added
- `-DryRun` parameter to simulate releases.
- `-WingetPkgsRepoPath` and `-SubmitToWinget` parameters to automate local winget-pkgs preparation (manifest copy, validate, local commit).
### Changed
- Script structure to support new parameters and winget submission preparation.

## [0.0.9] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Fixed
- Ensured old root-level ZIP archives are moved to `releases_archive` for proper rotation.
### Changed
- Final test run of the complete automated release script.

## [0.0.8] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Changed
- Final refinement to `Rotate-LocalReleaseArchives` function for robustness.
### Added
- This entry for the final test run.

## [0.0.7] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Added
- ZIPs moved to local 'releases_archive' folder.
- ZIPs no longer committed to Git repository.
- Rotation for local ZIP archives implemented in publish script.

## [0.0.6] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Added
- Integrated GitHub CLI for release creation and asset upload.
- Installer manifest URL is now updated automatically.

## [0.0.5] - YYYY-MM-DD_TIMESTAMP_PLACEHOLDER
### Added
- Placeholder for automated release v0.0.5.
