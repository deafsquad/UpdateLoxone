# Changelog

## [0.7.9] - 2026-02-21 06:27:56
### Fixed
- Fixed parallel Miniserver worker treating placeholder version strings (e.g., 'Checking...') as valid versions, which could cause update logic to skip or fail
  - Non-numeric version values from failed pre-checks are now detected and re-fetched with a warning log

## [0.7.8] - 2026-02-21 06:16:44
### Added
- Invocation parameter logging on startup ÔÇö logs all bound parameters, PowerShell version, username, and hostname after module load for easier troubleshooting

### Changed
- BurntToast module install and import now use background jobs with a 30-second timeout to prevent hangs on headless or remote sessions
- BurntToast failures are no longer fatal ÔÇö toast notifications gracefully degrade and the script continues without them
- NuGet provider and PSGallery trust are pre-configured before BurntToast install to prevent interactive prompts that could block unattended execution
- Bumped package version to 0.7.8 in all WinGet manifest files

### Fixed
- Fixed single-line miniserver list files causing errors in cache operations by wrapping `Get-Content` results with `@()` array subexpression to prevent PowerShell's single-element array unrolling

## [0.7.7] - 2026-02-21 05:30:40
### Changed
- Miniserver update trigger now verifies response before proceeding with polling
  - Validates HTTP status code (expects 200)
  - Parses XML `Code` attribute from Miniserver response to confirm acceptance
  - Logs full trigger response body and status for diagnostics
  - Reports clear failure reason when trigger is rejected or returns unexpected response
- Parallel workflow step mapping refactored from hardcoded counts to data-driven step definitions
  - Step totals are now derived dynamically from step definition arrays
  - Config and App step progressions built via iteration instead of manual assignment
- Removed "Fix Icons" as a separate visible progress step in parallel workflow
  - Icon fixing still runs after App and Config installation but no longer reports its own progress stage
  - App update steps reduced from 4 to 3 (Download, Install, Verify)
- Bumped package version to 0.7.7 in WinGet manifest files

### Fixed
- Miniserver update trigger no longer assumes success without response validation
  - Previously discarded trigger response with `Out-Null` and immediately reported success
  - Now detects and logs failed or rejected update triggers with specific failure reasons

## [0.7.6] - 2026-02-18 00:16:41
### Changed
- Increased Miniserver update trigger retry attempts from 3 to 5 to allow VPN tunnels adequate time to establish before failing
- Disabled redundant Loxone App shortcut icon fix in main script body (now handled inside `Install-LoxoneAppUpdate` workflow step)
- Updated release manifests to version 0.7.6 with new installer URL and SHA256 hash
- Release date updated to 2026-02-18 in locale manifest

### Fixed
- Fixed nested `claude` subprocess calls in `publish_new_release.ps1` failing when `CLAUDECODE` environment variable is set by saving and restoring it around the call

## [0.7.0] - 2026-02-13 02:49:53
### Added
- System restart detection for installer exit codes 3010 (ERROR_SUCCESS_REBOOT_REQUIRED) and 1641 (ERROR_SUCCESS_REBOOT_INITIATED)
- `RestartRequired` flag propagated through installation result objects, parallel workflow progress, and script global state
- Summary line warning when system restart is required after installation (e.g. VC++ Redistributable dependency)
- `/NORESTART` flag passed to Loxone Config installer to prevent automatic reboots during silent installation

### Changed
- Installer success evaluation now treats exit codes 3010 and 1641 as successful installations requiring restart
- Parallel workflow worker logs distinguish between clean installations and those requiring restart
- Sequential workflow step processing now checks for `RestartRequired` flag and propagates to global state
- Verification failure messages no longer append installer exit code when exit code indicates restart-required success
- Package version bumped to 0.7.0

## [0.6.9] - 2026-02-11 14:01:13
### Added
- **Miniserver generation detection**: New modules `LoxoneUtils.MiniserverGeneration.psm1` and `LoxoneUtils.MiniserverHardware.psm1` for detecting Gen1-Grey, Gen1-Green, and Gen2 Miniservers via UPNP/version endpoints and MAC prefix analysis
- **Network core module**: New `LoxoneUtils.NetworkCore.psm1` with singleton HttpClient, double-checked locking, and automatic test-mode detection via environment variables for fast network operations
- **Certificate helper module**: New `LoxoneUtils.CertificateHelper.psm1` with compiled C# delegates for thread-safe TLS certificate bypass in parallel/threaded contexts
- **Miniserver monitoring**: New `LoxoneUtils.Monitor.psm1` for managing `loxonemonitor.exe` during updates for debug logging
- **Real-time miniserver status updates**: `Send-MSStatusUpdate` function provides live progress through `ConcurrentQueue` for parallel update monitoring with state tracking (Updating, Installing, Rebooting, Verifying, Completed, Failed)
- **Miniserver update stage tracking**: Detailed stage transitions with millisecond-precision timing (Downloading → Installing → Rebooting → Verifying → Completed) logged with `[STAGE_TRANSITION]` markers
- **503 status code parsing**: Miniserver update polling now parses HTTP 503 response bodies to extract detailed status codes (530-534) for granular update progress
- **Timing-based state estimation**: When Miniservers return 503 without error detail codes, elapsed time is used to estimate the current update phase
- **Downloads folder cleanup**: New `Invoke-DownloadsFolderCleanup` function with configurable age and count retention policies
- **Update trigger retry logic**: Miniserver update trigger now retries up to 3 times with progressive delays (2s, 4s, 6s) before failing
- **Poll attempt retry logic**: Each polling iteration retries up to 3 times with 2-second delays for transient network errors
- **Loxone App process termination before install**: `Start-LoxoneForWindowsInstaller` now kills running Loxone processes (up to 5 attempts) before starting installation
- **In-memory logging for parallel mode**: `ConcurrentBag`-based in-memory log collection when `LOXONE_PARALLEL_MODE` is set, avoiding file I/O serialization bottlenecks
- **Single test runner**: New `tests/run-single-test.ps1` for running individual test files
- **Archived modules directory**: Added `LoxoneUtils/archived_modules/` to `.gitignore`

### Changed
- **Parallel workflow engine rewrite**: `LoxoneUtils.ParallelWorkflow.psm1` significantly expanded (~2200 lines added) with `ConcurrentBag`/`ConcurrentDictionary` for thread-safe state management, direct ThreadJob execution, and real-time progress queue processing
- **Miniserver communication modernized**: `Invoke-MiniserverWebRequest` now routes through NetworkCore for fast operations in test mode, with proper HttpClient integration and enhanced error detail capture including inner exception chains
- **HTTPS certificate handling unified**: Replaced inline `ServerCertificateValidationCallback = { $true }` with `Set-CertificateValidationBypass` / `Clear-CertificateValidationBypass` from CertificateHelper across all Miniserver functions for thread safety
- **Gen2 Miniserver security**: HTTPS failures on Gen2 Miniservers no longer fall back to HTTP; only Gen1 Miniservers attempt HTTP fallback
- **Invoke-MSUpdate signature simplified**: Removed UI-coupled parameters (`StepNumber`, `TotalSteps`, `IsInteractive`, `ErrorOccurred`, `AnyUpdatePerformed`, `MSCounter`, `TotalMS`); added `ProgressQueue` parameter for decoupled real-time status reporting
- **Password handling flexibility**: `Invoke-MSUpdate` now accepts both `SecureString` and plain text passwords, enabling simpler credential passing in parallel/serialized contexts
- **Miniserver cache enhanced**: `LoxoneUtils.MiniserverCache.psm1` updated with generation info storage (4th field in cached entries)
- **Connectivity check improvements**: Quick connectivity checks now use NetworkCore when available, with increased HTTPS timeout (3s vs 1s) and downgraded false-negative logging from WARN to DEBUG
- **UpdateLoxone.ps1 main script expanded**: Major expansion (~900 lines added) with parallel execution orchestration, enhanced progress reporting, and improved workflow step coordination
- **Workflow steps expanded**: `LoxoneUtils.WorkflowSteps.psm1` significantly extended (~680 lines added) for parallel-aware execution
- **Test runner enhancements**: `run-tests.ps1` expanded with improved test-level parallelism, better filtering, and additional output modes
- **Module manifest updated**: `LoxoneUtils.psd1` updated with new nested modules (NetworkCore, CertificateHelper, MiniserverGeneration, MiniserverHardware, Monitor)
- **Logging mutex creation**: Removed `Write-Debug`/`Write-Warning` during mutex initialization to prevent recursive logging loops
- **`TimeoutSec` parameter type**: Changed from `[int]` to `[decimal]` in `Invoke-MSUpdate` to support fractional seconds for faster test timeouts
- **Publish release script enhanced**: `publish_new_release.ps1` expanded (~310 lines) with improved release workflow
- **UpdateLoxoneMSList.txt.example expanded**: Additional documentation and examples for Miniserver list configuration
- **SSL error diagnostics**: Full inner exception chain traversal (up to 10 levels) logged with `[SSL/TLS Error Chain]` markers and root cause identification
- **Test coverage module**: `LoxoneUtils.TestCoverage.psm1` updated with expanded analysis capabilities
- **Installer version detection**: `Test-ExistingInstaller` now handles installers without `FileVersion` metadata by falling back to file size validation for App installers (>10MB)

### Fixed
- **Parallel mode file logging contention**: Logging in parallel mode now skips mutex acquisition and file I/O entirely, using thread-safe `ConcurrentBag` instead, eliminating deadlocks and serialization bottlenecks
- **Credential null checks**: Added defensive null checks for `$Credential` object before accessing `.UserName` and `.GetNetworkCredential()` across trigger, polling, and verification code paths, with clear error messages
- **HTTPS polling with certificate bypass**: Added `SkipCertificateCheck` to verification polling parameters for PS7 HTTPS connections
- **Parallel context `$MyInvocation` errors**: `Invoke-MSUpdate` now skips `Enter-Function` in parallel mode to avoid `$MyInvocation` serialization failures in ThreadJob contexts
- **Null `MSUri` guard**: Early return with error result when `MSUri` is null, preventing null reference exceptions in parallel workers
- **Shortcut icon fix removed**: Commented out Loxone App shortcut icon fix code as Loxone fixed the installer bug (2024-11), with documentation for re-enabling if needed
- **Network module improvements**: `LoxoneUtils.Network.psm1` enhanced with retry logic and CRC verification improvements
- **Thread safety improvements**: `LoxoneUtils.ThreadSafe.psm1` updated for more robust cross-thread state management with named mutex
- **Toast notification reliability**: `LoxoneUtils.Toast.psm1` improved with better error handling and `Submit-BTNotification` with Reminder scenario
- **Test compatibility fixes**: Multiple test files updated for compatibility with new module structure and parallel testing patterns

## [0.6.8] - 2025-08-09 01:07:48
### Changed
- Modified installer behavior to provide real-time progress updates during Loxone Config and App installations
- Improved toast notification updates to prevent auto-dismissal by refreshing every 2 seconds during installations
- Enhanced Miniserver cache validation to handle clock skew and future timestamps gracefully
- Optimized parallel workflow progress worker to use persistent global toast data for consistent updates
- Updated main update logic to always run MS PreCheck for accurate version detection before proceeding with updates

### Fixed
- Fixed installer processes hanging indefinitely by implementing 5-minute timeout for Config installer
- Fixed toast notifications auto-dismissing during long-running operations by adding periodic refresh mechanism
- Fixed cache validation incorrectly rejecting entries with minor clock skew (within 1 minute tolerance)
- Fixed toast notification binding issues in parallel workflow by maintaining same dataframe reference
- Fixed unnecessary update attempts when all Miniservers are already current by checking actual versions via PreCheck
- Fixed missing cache timestamp handling that could cause invalid cache entries to be accepted

## [0.6.7] - 2025-08-09 00:34:35
### Added
- **Parallel Workflow Execution** - Major performance improvement for update process
  - Added `-Parallel` switch to enable concurrent downloads and installations
  - Config and App downloads/installs run simultaneously instead of sequentially
  - Miniserver updates process concurrently with configurable concurrency limits
  - ThreadJob-based architecture for efficient resource utilization
  - Automatic fallback to sequential mode if issues detected
- **Enhanced Progress Tracking for Parallel Mode**
  - Component-specific progress bars (Config, App, Miniservers)
  - Real-time download speeds and remaining time per component
  - Elapsed time tracking with proper timer display (⏱️ mm:ss format)
  - Weighted miniserver progress calculation (Init=0, Update=2, Reboot=3, Wait=4, Complete=5)
  - Status symbols for miniserver stages (🔍🔄🚀⏳✓✗)
- **Configuration File Support** - `UpdateLoxone.config.json`
  - `UseParallelExecution` - Enable parallel mode by default
  - `MaxConcurrency` - Control download/install concurrency
  - `MaxMSConcurrency` - Control miniserver update concurrency
  - Command-line switches override configuration settings
- **Console Progress Display** - Alternative to toast notifications
  - ASCII progress bars for non-toast environments
  - Real-time updates with component status
  - Individual miniserver status tracking
  - Automatic fallback when toast notifications unavailable
- **Thread-Safe State Management**
  - New `LoxoneUtils.ThreadSafe` module with mutex-protected operations
  - `Update-WorkflowState` for safe concurrent state updates
  - `Get-WorkflowState` for consistent state reads across threads
  - Named mutex for cross-process synchronization

### Changed
- **Progress Worker Architecture**
  - Separated progress tracking into dedicated worker thread
  - Prevents UI freezing during heavy operations
  - Maintains toast data binding throughout workflow
  - Graceful shutdown with proper cleanup
- **Enhanced Logging**
  - Comprehensive parallel mode detection logging
  - Thread/job lifecycle tracking
  - Performance metrics for concurrent operations
  - Debug traces for troubleshooting parallel issues

### Fixed
- **Toast Notification Issues in Parallel Mode**
  - Fixed progress bars resetting to 0% when Config completes
  - Fixed App timer showing incorrect values after Config finishes
  - Fixed "Waiting..." status during file validation (now shows "Checking existing files...")
  - Fixed timer not starting until installation begins
  - Fixed toast updates from main script interfering with progress worker
- **Threading Issues**
  - Fixed ThreadJob pool exhaustion with proper cleanup
  - Fixed Ctrl+C handler to stop all worker threads
  - Fixed environment variable scope issues in finally blocks
  - Fixed race conditions between worker threads

## [0.6.6] - 2025-07-24 16:38:47
### Changed
- **Improved test coverage calculation methodology** - Coverage now includes ALL functions without exclusions
  - Test infrastructure functions are now included in coverage calculations
  - Coverage percentages reflect true code coverage across the entire codebase
  - Provides more accurate representation of actual test coverage
- **Enhanced function usage detection in TestCoverage module**
  - Added comprehensive PowerShell patterns for detecting function calls
  - Improved regex patterns to catch dynamic invocations, scriptblocks, and event handlers
  - Better detection of functions used in pipelines, subexpressions, and background jobs
  - Fixed regex escaping issues that could cause pattern matching failures
- **Updated KPI metrics to use positive indicators**
  - Replaced "DeadCode%" with "ActiveCode%" (percentage of functions actively used)
  - Replaced "DeadTests%" with "ActiveTests%" (percentage of tests for existing functions)
  - KPI format now shows: TestCount/TestExecution%/TestSuccess%/Coverage%/ActiveCode%/ActiveTests%
  - Provides more intuitive metrics where higher values are better
- **Optimized test coverage report generation**
  - Implemented single-pass analysis to improve performance
  - Eliminated temporary file creation during report generation
  - Report data is now collected once and reused throughout the process
- **Enhanced entry point detection for exported functions**
  - Exported functions following PowerShell verb-noun patterns are recognized as entry points
  - Prevents false positives for dead code on public APIs
  - Better handling of functions designed for external invocation

### Fixed
- **Fixed regex pattern escaping in function usage detection**
  - Function names are now properly escaped before use in regex patterns
  - Prevents regex errors when function names contain special characters
  - Ensures accurate detection of function calls throughout the codebase

### Deprecated
- **GenerateReport parameter in Get-TestCoverage** - Use New-TestCoverageReport for report generation instead

## [0.6.5] - 2025-07-20 07:25:17
### Added
- Added automatic staging of untracked files in publish script when user selects 'Y'
- Added 'SELECT' option in publish script to choose specific files to add
- Added success/failure status display for each file being staged
- Added progress percentage calculation to subprocess toast updates
- Added debug logging to track test count discrepancies and LiveProgress state

### Changed
- Improved publish script workflow to continue with release process after staging files instead of exiting
- Updated uncommitted changes list after adding files in publish script

### Fixed
- Fixed live progress notification showing incorrect test counts (257/257 instead of 261 or 258)
- Fixed double-counting of SYSTEM tests in total count
- Fixed extra test count increment when updating toast after subprocess
- Fixed notification showing 253/257 instead of 257/257 after SYSTEM tests completed
- Fixed duplicate skipped tests in detailed output (was showing 90 instead of 45)
- Fixed SystemTests counts being overwritten after RunAsUser tests complete
- Fixed undefined function Get-LoxoneConfigToastAppId causing toast updates to fail
- Added proper merging of regular System test results with RunAsUser results
- Ensured notification shows correct completion status with runtime and pass rate

## [0.6.4] - 2025-07-20 05:53:16
### Fixed
- Fixed live progress notification to show correct total test count (257 instead of 253) by including subprocess SYSTEM test results
- Fixed test discovery to dynamically include RunAsUser SYSTEM tests only when admin privileges are available and the test script exists
- Fixed notification counters to update after RunAsUser SYSTEM tests complete via subprocess
- Fixed toast notification to force update with new totals after subprocess tests finish

## [0.6.3] - 2025-07-20 05:34:24
### Added
- Early exit detection in publish script when no changes are available for release
  - Automatically detects when there are no uncommitted changes or unpushed commits
  - Shows clear message explaining why the script is exiting
  - Prevents unnecessary processing when there's nothing to release

### Fixed
- Corrected parameter name in test coverage module to resolve warnings
  - Fixed `Get-TestInfrastructureFunctions` call to use `-ModulePath` instead of `-TestPath`
  - Eliminates 'TestPath parameter not found' warnings during test runs
  - Ensures proper function parameter matching according to function definition

## [0.6.2] - 2025-07-20 03:51:15
### Added
- Display of file changes for unpushed commits in publish script
  - Shows file status (Added/Modified/Deleted/Renamed) for each commit
  - Applied to both resume state display and main flow display
  - Helps users understand exactly what changes are in each commit

### Changed
- Enhanced Claude changelog validation and error handling
  - Improved prompt to explicitly prevent changelog boilerplate text
  - Added clearer instructions about response format
  - Better regex matching for UPDATED_CHANGELOG markers
  - Save problematic responses to debug files for analysis

### Fixed
- Improved error messages with debug output for troubleshooting changelog generation
- Fixed CHANGELOG validation to properly detect and remove format declaration strings in AI responses
- Resolved issues with changelog boilerplate removal that could slip through validation

## [0.5.8] - 2025-07-20 03:14:39
### Added
- Enhanced resume operation with detailed commit information display
  - Added display of commit bodies and multi-line messages for better context
  - Added comprehensive Git state display showing uncommitted changes and unpushed commits before proceeding
  - Added CHANGELOG preview showing Unreleased section that will be converted
- Improved dry-run mode functionality
  - Added clear dry-run mode summary showing what actions will be performed vs skipped
  - Added support for skipping test execution in dry-run mode with proper state tracking
  - Added descriptive commit messages for dry-run releases indicating they are test runs
- Enhanced validation for MSI and manifest generation
  - Added Git state hash validation to ensure MSI and manifests are recreated if code changes after initial creation
  - Added automatic re-creation of artifacts when codebase changes are detected during resume

### Changed
- Reorganized CHANGELOG.md structure to have format declaration at the top instead of after version entries
- Improved release script error handling with explicit exit code checks for all Git commands
  - Added error handling for `git branch --show-current` operations
  - Added error handling for `git status --porcelain` operations
  - Added error handling for `git log` operations
- Enhanced commit message formatting for both dry-run and production releases
  - Dry-run commits now include explanatory body text about their purpose
  - Production releases include descriptive automated release note
- Updated Git state display in resume operations
  - Changed "tests_passed" to "tests_completed" for clarity
  - Added checksum comparison showing if code changed since tests ran
- Improved changelog validation to detect and reject when AI includes format declarations in responses

### Fixed
- Fixed BOM (Byte Order Mark) issues in manifest files by adding UTF-8 BOM prefix
- Fixed potential issues with uncommitted changes and unpushed commits not being properly detected
  - Ensured variables are set for later use even when not in resume context
  - Added fallback initialization for all Git state variables
- Fixed CHANGELOG validation to properly detect format declaration strings in AI responses

## [0.5.2] - 2025-07-20 01:32:51
### Changed
- Enhanced release process with Git state verification to ensure tests remain valid between resume operations
  - Added state hash tracking to detect code changes after test completion
  - Improved test re-run logic when codebase changes are detected
- Improved changelog generation to handle uncommitted changes
  - Now processes uncommitted changes when no unpushed commits exist
  - Better handling of working tree diffs for changelog generation
- Added pre-test check for untracked files with interactive prompt
  - Warns users about files that won't be included in release
  - Allows opportunity to add files before test execution

## [0.5.0] - 2025-07-20 00:22:58
### Fixed
- Fixed test categorization discrepancy in test runner
  - Unit tests with "System" in filename were incorrectly categorized as System tests
  - Test discovery showed System=8 but only 6 were actual System tests (2 were Unit tests)
  - Updated categorization logic to check folder path before filename pattern
  - Now correctly excludes Unit folder files from System test categorization
  - Consistent categorization priority: Tags > Folder Path > Filename Pattern
- Fixed test discovery to properly count RunAsUser System tests
  - Discovery now accounts for the 4 RunAsUser tests that run via invoke-system-tests.ps1
  - System test count in discovery summary now shows correct total (10 instead of 6)
- Fixed git diff syntax error in publish script
  - Changed from incorrect `origin/branch...HEAD` to correct `origin/branch..HEAD`
  - Prevented script from continuing with broken state when commands fail
- Fixed CHANGELOG format validation in publish script
  - Added validation to reject Claude responses that include changelog headers
  - Ensures Claude only returns the Unreleased section content
  - Prevents malformed CHANGELOG entries with duplicate headers
  - Cleans up state file on validation errors
  - Only sends Unreleased section to Claude (not full changelog) to avoid confusion
  - Properly replaces [Unreleased] with actual version after Claude updates

### Added
- Comprehensive error handling for ALL commands in publish script
  - Every git command now checks $LASTEXITCODE
  - Every gh (GitHub CLI) command has error handling
  - File operations (Get-Content) use -ErrorAction Stop
  - Script exits immediately on any command failure
  - Clear error messages indicate exactly what failed
  - Prevents silent failures and broken release states

### Changed
- Improved automated commit squashing in publish script
  - Removed manual prompt for squashing - now automatically combines commits
  - Integrated Claude CLI for automatic changelog verification
  - Uses `claude -p` command with piped input for seamless integration
  - Falls back gracefully if Claude CLI is not available
  - Eliminates manual copy-paste step for AI verification
- Enhanced publish script error handling and validation
  - All git and gh commands now have comprehensive error checking
  - State file is properly cleaned up on any error
  - Validates Claude's changelog response format before applying
- Enhanced release resumption with detailed state information
  - Shows current git state (branch, commits, changes) when resuming
  - Displays release progress with checkmarks for completed steps
  - Checks if GitHub release already exists
  - Clear explanation of what happens when choosing Y (resume) or N (start fresh)
  - Warnings when uncommitted changes or unpushed commits are detected

### Added
- Comprehensive changelog generation with full git diff analysis
  - Claude now receives complete git diff from origin/master to HEAD
  - Analyzes actual code changes, not just commit messages
  - Ensures 100% coverage of all changes in the changelog
  - Generates complete Unreleased section from scratch
  - Captures changes that might be missed in commit messages
  - No size limits - sends full diff for complete analysis
  - Proper error handling with exit on Claude failures
  - Saves prompt to file on error for manual processing

## [0.4.9] - 2025-07-19 23:24:39
### Changed
- Allow release process to continue when CHANGELOG is empty but unpushed commits exist
  - Script now recognizes that changes may be documented in commit messages
  - AI verification will merge commit messages with CHANGELOG entries
  - Prevents blocking releases when changes are in commits but not yet in CHANGELOG
  - Supports mixed documentation workflow (some in CHANGELOG, some in commits)

## [0.4.8] - 2025-07-19 22:51:32
### Fixed
- Fixed tag push timing in release script
  - Tags are now pushed separately after commit to ensure availability for GitHub release creation
  - Prevents "tag exists locally but has not been pushed" error during release process

## [0.4.7] - 2025-07-19 22:26:49
### Fixed
- Added comprehensive carriage return protection to publish script
  - All version strings are now sanitized when read from manifests, state files, or CHANGELOG
  - State management functions strip carriage returns from both keys and values
  - CHANGELOG parsing handles version headers with embedded carriage returns
  - Prevents version string corruption that could break release process
  - Ensures consistent version formatting across all script operations

### Changed
- Simplified release process to single-push approach
  - Eliminated second commit/push for installer URL update
  - Uses predictable GitHub release URL pattern in manifests
  - Creates and pushes tag with the release commit
  - Removed redundant commit link from release notes
  - Cleaner, more atomic release process

## [0.4.6] - 2025-07-19 07:29:58
### Fixed
- Test coverage enforcement compliance
  - Added workaround for Get-ScheduledTask timeout issue in PowerShell 7
  - Fixed test runner to properly handle CI mode with live progress
  - Resolved duplicate test execution in coverage mode

## [0.4.5] - 2025-07-19 06:29:23
### Added
- Resumability feature for release script
  - Added state tracking system using `.release-progress` file
  - Script can now resume from any interruption point
  - Automatic detection of completed steps (tests, CHANGELOG, MSI creation, etc.)
  - Environment variable `RESUME_RELEASE=true` for CI/automation
  - Proper cleanup of state file on successful completion

### Fixed
- Fixed missing App version in final update notification
  - Added cases for "InstallSuccessful" and "UpdateSuccessful" statuses
  - Final summary now correctly shows "✓ APP (InternalV2) 2025.7.18.0" instead of "🔄 APP (InternalV2)"
- Fixed test runner Count property errors under strict mode
  - Added null checks before accessing .Count properties throughout test runner
  - Tests now run successfully when called from publish script with strict mode enabled
- Fixed GitHub release creation being skipped when resuming
  - Moved release creation logic outside of commit creation block
  - Release creation now runs regardless of resume state

## [0.4.4] - 2025-07-19 02:53:24
### Added
- Dry run version management improvements
  - Auto-increment version for repeated dry runs to avoid duplicate MSI installations
  - Skip CHANGELOG requirement for auto-incremented dry run versions
  - Track last dry run version in `.last-dryrun-version` file
- Comprehensive test suite with 100% module coverage
  - Created 39 test files covering all 11 PowerShell modules
  - Implemented four test types per module: Simple, Working, Characterization, and Full tests
  - Added test runner scripts with CI/CD support
  - Created test documentation and summaries
  - All modules now have complete test coverage: Logging, Utility, Network, Installation, Miniserver, UpdateCheck, WorkflowSteps, ErrorHandling, System, Toast, and RunAsUser
- Automated testing in release process
  - Modified `publish_new_release.ps1` to run full test suite before proceeding
  - Release now fails if any tests fail, ensuring quality
  - Added `-CI` and `-PassThru` parameters to test runner for automation
  - Added `-LiveProgress` parameter to show real-time test progress during release
- Architectural analysis and recommendations
  - Created `CLAUDE.md` with detailed code analysis and improvement recommendations
  - Identified and documented dead code in UpdateCheck module
  - Created `REFACTORING_ANALYSIS.md` documenting the architectural changes
  - Created `REFACTOR_TO_PLUGIN_ARCHITECTURE.md` with detailed plugin architecture design
- Test infrastructure improvements
  - Set up Pester v5 testing framework
  - Created proper test directory structure (Unit, Integration, Fixtures)
  - Added characterization tests to document actual behavior
  - Implemented test helpers and utilities
  - Added UTF-8 BOM to test runner script to fix PowerShell 5.1 Unicode parsing issues

### Changed
- Reorganized test directory structure
  - Removed obsolete `test/` folder completely
  - Created new `tests/` structure with Unit, Integration, and Fixtures subdirectories
  - Updated all test imports to use new module paths
- Enhanced release process
  - Release script now runs comprehensive test suite first
  - Added test result summary display in release output
  - Release aborts if tests fail or no tests pass
- Test runner improvements
  - Fixed coverage summary not displaying in CI mode
  - Added special handling for COVERAGE and SUMMARY log levels in CI mode
  - Improved coverage report positioning to appear before test summary
  - Removed hardcoded verbose flags from TestCoverage module
  - Fixed coverage module path resolution issue
  - Suppressed Pester test discovery output in CI mode by redirecting console streams
  - Fixed missing test statistics in CI mode by adding SUMMARY level to all test result outputs
  - Fixed "Test discovery complete" not showing in CI mode by adding SUMMARY level
  - Suppressed Pester discovery output ("Test run was skipped", "Tests completed in Xms") in all modes
  - Refactored test summary display to use dynamic discovery instead of hardcoded test types
  - Fixed System test duration not displaying by improving duration handling in dynamic summary
  - Added duration placeholder (--:---.---) when tests ran but duration is missing
  - Fixed System test skip reason showing when only some tests were skipped (now only shows when ALL are skipped)
  - Fixed System test duration showing as 0 by ensuring minimum duration for categories that ran tests
  - Added duration estimation for SYSTEM tests when no duration is reported by PsExec helper
  - Fixed System Test Skip Reason showing at top level when RunAsUser tests pass
  - Improved skip reason display logic to show contextually appropriate messages
- Enhanced publish script to stage all project files instead of selective files
  - Now uses `git add -A` to include all changes (new, modified, deleted)
  - Added pre-flight check for untracked files with user confirmation
  - Shows detailed list of files being staged with their status
  - Prompts user to handle untracked files before proceeding
  - Ensures all project changes are included in release commits
- Replaced ZIP packaging with MSI installer for winget compatibility
  - Now creates proper MSI installer using PSMSI module
  - MSI installs to Program Files with Start Menu shortcut
  - Supports proper uninstallation through Windows Add/Remove Programs
  - Enables future submission to winget-pkgs repository
  - Updated all publish script references from ZIP to MSI
  - Installer manifest now uses `InstallerType: msi` instead of `zip`
- Enhanced publish script to include release commit link in GitHub release notes
  - Release notes now include a direct link to the actual branch commit
  - Makes it easier to trace releases back to their source commits
  - Improves transparency by linking to the real commit instead of just the tag
- Optimized `LoxoneUtils.Toast.psm1` module
  - Reduced code size by ~50% through consolidation of redundant code
  - Replaced custom logging with centralized logging functions (Write-Log, Enter-Function, Exit-Function)
  - Improved function organization and separation of concerns
  - Preserved critical data binding fix to prevent toast dismissal
  - Fixed PowerShell 5.1 compatibility issues (removed null-coalescing operator)
  - Module now properly handles initialization when loaded before logging module
  - Removed `Get-LoxoneConfigToastAppId` from exports (now internal)
  - Added `Reset-ToastDataBinding` to exports for testing scenarios

### Fixed
- MSI installer now properly redirects logs to %LOCALAPPDATA%\UpdateLoxone when installed in Program Files
- Fixed MSI upgrade behavior by using stable UpgradeCode
- Removed version revert for dry runs to allow proper version increment testing
- Fixed publish script error handling
  - Fixed incorrect test runner parameter from `-GenerateCoverage` to `-Coverage`
  - Added exit code checking after test execution to prevent releases when tests fail
  - Added error handling for git push operations with helpful error messages
  - Script now properly exits with code 1 when tests fail or git operations fail
  - Prevents creating releases with broken code
- Fixed app update showing rocket emoji (🚀) instead of update arrow (⬆️)
  - `Invoke-InstallLoxoneApp` and `Invoke-InstallLoxoneConfig` now properly detect updates vs new installs
  - Action type is determined dynamically based on InitialVersion presence
  - Toast notifications and log messages now correctly reflect the action being performed
- Identified missing return statement in `New-LoxoneComponentStatusObject` (though function is dead code)
- Documented parameter naming inconsistencies across modules
- Identified and documented functions that are exported but not used
- Fixed log rotation timestamp duplication issue
  - Log files no longer get double timestamps during rotation (e.g., `file_20250603_120000_20250603_120500.log`)
  - Files with existing timestamps are now rotated without adding additional timestamps
  - Simplified cleanup logic to properly group files by prefix and clean up old logs
  - Improved regex patterns to handle both legacy double-timestamp files and new single-timestamp files
- Toast notification fixes
  - Fixed toast notification auto-dismiss issue
    - Toast notifications were dismissing after ~6 seconds during long operations
    - Root cause: `New-BurntToastNotification` doesn't support scenarios that prevent auto-dismiss
    - Solution: Switched to `Submit-BTNotification` with `Reminder` scenario
    - Toast notifications now remain visible until user interaction or script updates
  - Fixed progress bar getting stuck at 98% when transitioning from download to installation
  - Fixed toast losing foreground state and auto-dismissing after download completion
  - Fixed stale text appearing when reusing existing toast notifications
  - Added comprehensive runtime tracking for all workflow steps
  - Made toast text configuration-driven with dynamic step categories
  - Added visual symbols (✓, ✗, 🔍, ⬇️, 📦, ⚙️, 🔄, 🏁, ⏳, 🚀) throughout messages
  - Fixed Loxone app icon missing in Start Menu shortcut
- Final notification improvements
  - Added proper sorting (APP first, then Conf, then MS)
  - Fixed app build date display to show just the date (YYYY-MM-DD)
  - Added channel information display for all components
  - Replaced verbose status text with symbols
  - Shortened final message to show only what was updated

### Security
- Documented secure credential handling patterns for Miniserver connections
- Added recommendations for least-privilege Miniserver user setup
- Identified webhook URL exposure (low risk - posting only)
- Recommended credential encryption strategies for future implementation


### Documentation
- Created comprehensive test documentation (`TEST_SUMMARY.md`)
- Added module-specific test summaries for complex modules
- Created testing progress tracking documentation
- Updated all `.md` files with current project state
- Added plugin architecture design document
- Documented refactoring strategy and implementation phases

## [0.3.8] - 2025-06-01 04:03:09
### Changed
- Enhanced `README.md` with a more detailed explanation of the Miniserver update process, including:
    - Version checking against the target Loxone Config version.
    - Authentication handling.
    - Usage of the `-SkipCertificateCheck` parameter.
    - The `updatelevel` validation step on the Miniserver.
    - How the update is triggered via `/dev/sys/autoupdate`.
    - Polling and verification of the update status.
## [0.3.7] - 2025-06-01 03:48:28
### Changed
- Updated `README.md` to clarify that the `-SkipCertificateCheck` parameter is primarily for Miniserver connections and does not affect SSL/TLS validation for downloading Config/App installers.
    - Corrected the Mermaid diagram in `README.md` to remove the incorrect reference to `-SkipCertificateCheck` for the Loxone Config download step.
    - Updated the parameter description for `-SkipCertificateCheck` to accurately reflect its scope.
## [0.3.6] - 2025-05-30 20:38:41
### Fixed
- Resolved an issue in `UpdateLoxone.ps1` where the `Update Miniservers` step could fail with "Cannot bind argument to parameter 'ConfiguredUpdateChannel' because it is an empty string". The script now correctly defaults to the "Test" channel if the `-Channel` parameter is not provided or is an empty string, ensuring `Invoke-UpdateMiniserversInBulk` receives a valid channel.
## [0.3.5] - 2025-05-30 20:33:45
### Added
- Implemented an `updatelevel` check before attempting Miniserver updates.
    - The script now queries `/dev/cfg/updatelevel` on the Miniserver.
    - If the reported `updatelevel` (e.g., "Alpha", "Beta", "Release") does not match the configured update channel for the script (with "Test" channel mapping to "Alpha"), an error is raised.
    - The error message informs the user about the mismatch and provides a URI (e.g., `https://user:pass@ip/dev/cfg/updatelevel/$Channel`) to set the correct `updatelevel` on the Miniserver.
    - This check is performed in `LoxoneUtils.Miniserver.psm1` and integrated into the main update workflow.
### Fixed
- Corrected a typo in a log message within `Test-LoxoneMiniserverUpdateLevel` in `LoxoneUtils.Miniserver.psm1` (related to `$scheme:`) that caused a "Variable reference is not valid" error during script import/execution. The variable is now correctly referenced as `${scheme}`.

## [0.3.4] - 2025-05-30 18:48:00
### Fixed
- Corrected an issue in `Update-MS` within `LoxoneUtils.Miniserver.psm1` where a plain string password was passed to `Invoke-MSUpdate` instead of a `SecureString`, causing authentication failures on local machines. The password is now correctly converted to `SecureString`.
## [0.3.3] - 2025-05-30 04:48:00
### Changed
- `Get-ChangelogNotesForVersion` now reads the changelog file directly.
### Added
- This entry tests the direct file read approach within the function.
## [0.3.2] - 2025-05-30 04:46:40
### Added
- Testing parameter splatting for `Get-ChangelogNotesForVersion`.
## [0.3.1] - 2025-05-30 04:46:04
### Changed
- Release notes will now be passed to `gh release create` via `--notes-file` for robustness.
### Added
- This entry is to test the `--notes-file` approach.
## [0.3.0] - 2025-05-30 04:45:19
### Added
- Test for v0.3.0. This should finally work.
- More detailed debug logging for changelog parsing.
## [0.2.9] - 2025-05-30 04:44:11
### Added
- This is a test for version 0.2.9.
- Release notes should be correctly extracted from this section.
## [0.2.8] - 2025-05-30 04:42:22
### Added
- Final test: Release notes from this section, with Get-Content fix.
## [0.2.7] - 2025-05-30 04:41:16
### Added
- Placeholder for testing automated release v0.2.7 with full changelog notes.
## [0.2.6] - 2025-05-30 04:39:53
### Added
- Test: Release notes will be populated from this section.
## [0.2.5] - 2025-05-30 03:12:31
### Fixed
- Corrected authentication logic in `Invoke-MSUpdate` within `LoxoneUtils.Miniserver.psm1`:
    - Added `$UsernameForAuthHeader` and `$PasswordForAuthHeader` parameters to `Invoke-MSUpdate`.
    - `Update-MS` now passes the manually parsed (non-URL-decoded) username and password to `Invoke-MSUpdate`.
    - `Invoke-MSUpdate` now prioritizes these passed-in raw credentials to construct the `Basic Authorization` header for its `Invoke-WebRequest` calls (both for triggering the update and for polling). This resolves 401 errors when passwords contain special characters.
    - The original `$Credential` object (with potentially URL-decoded password) is only used as a fallback if raw credentials are not available.
- Fixed a syntax error in `Invoke-MSUpdate` caused by a duplicated `try` statement, which led to PowerShell parsing errors.
## [0.2.4] - 2025-05-30 03:07:24
### Fixed
- Comprehensively reworked the initial version check logic in the `Update-MS` function (`LoxoneUtils.Miniserver.psm1`) to correctly handle authentication with special characters in passwords, while preserving the HTTPS-first connection attempt for `http://` entries.
    - Manually parsed credentials (username and non-URL-decoded password) are now prioritized for constructing the `Basic Authorization` header for *all* authenticated `Invoke-WebRequest` calls (both initial HTTPS attempts and HTTP fallbacks).
    - The problematic `$credential` object (which uses a URL-decoded password from `[System.UriBuilder]`) is no longer used for Basic Authentication if manual credentials are available, thus preventing 401 errors.
    - For `http://` entries, an HTTPS connection is attempted first. If it fails, an HTTP fallback occurs. Both attempts use the manual `Authorization` header if credentials are provided.
    - For `https://` entries, a direct HTTPS connection is attempted, using the manual `Authorization` header if credentials are provided.
    - Ensured `-UseBasicParsing` is consistently applied for HTTP requests.
## [0.2.3] - 2025-05-30 03:06:46
### Fixed
- Corrected an issue in `publish_new_release.ps1` where the script would fail with a "property 'Count' cannot be found" error if `Get-ChildItem` returned no candidate manifest files or no archive files. Ensured that variables intended to hold collections are always initialized as arrays.
## [0.2.2] - 2025-05-30 02:53:00
### Fixed
- Refined `Get-MiniserverVersion` in `LoxoneUtils.Miniserver.psm1` to correctly handle Miniserver entries specifying `http://`. It now directly attempts an HTTP connection with manual Authorization headers and `-UseBasicParsing`, instead of first attempting an HTTPS call which could lead to "AllowUnencryptedAuthentication" errors if a `$credential` object was inadvertently used with an HTTP URI during the initial HTTPS probe.
## [0.2.1] - 2025-05-30 02:50:15
### Fixed
- In `Get-MiniserverVersion` within `LoxoneUtils.Miniserver.psm1`, explicitly set `$iwrParams.Credential = $null` during the HTTP fallback when a manual `Authorization` header is used. This is a further measure to prevent PowerShell from attempting to send credentials in a way that triggers the "AllowUnencryptedAuthentication" warning/error, even when a manual header is present.
## [0.2.0] - 2025-05-30 02:47:34
### Fixed
- Implemented manual parsing for username and password within `Get-MiniserverVersion` in `LoxoneUtils.Miniserver.psm1` when constructing the `Authorization` header for HTTP Basic Auth. This ensures the literal password string from the `MSEntry` is used, preventing `[System.UriBuilder]` from URL-decoding characters like `%` in the password, which was causing 401 errors.
- Ensured that the URI scheme is explicitly set to HTTP for the fallback attempt in `Get-MiniserverVersion`.
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
