# Loxone Auto Update Script (UpdateLoxone.ps1)

This PowerShell script automates the process of checking for, downloading, and installing updates for Loxone Config software and the Loxone App. It orchestrates the entire update workflow, including handling parameters, managing execution context (re-launching as the current user if initially run as SYSTEM), and registering a scheduled task for regular execution. The script can also trigger updates on configured Loxone Miniservers based on the installed Loxone Config version. It relies on a suite of `LoxoneUtils` modules for specific functionalities like logging, network operations, and installation tasks.

## Execution Flow Diagram

```mermaid
graph TD
    A[UpdateLoxone.ps1 Start] --> B(Parse Script Parameters);
    B --> C{Initial Run as SYSTEM?};
    C -- Yes --> D("Relaunch as Current User <br/> (LoxoneUtils.RunAsUser) <br/> with admin privileges <br/> if initially elevated");
    C -- No / Subsequent Run --> E(Import LoxoneUtils Modules);
    D --> E;
    E --> F("Initialize Workflow Context <br/> Paths, Logging, Versions <br/> (LoxoneUtils.Utility, <br/> LoxoneUtils.Logging)");
    F --> G{'-RegisterTask' Parameter?};
    G -- Yes --> H("Register/Update Sched. Task <br/> Runs as SYSTEM (highest priv.) <br/> (LoxoneUtils.System)");
    H --> ZTask["Exit (Task Registered)"];
    G -- No --> I("Fetch Update Prerequisites <br/> Check Loxone XML (local vs. remote) <br/> Uses -Channel and <br/> -UpdateLoxoneAppChannel <br/> (LoxoneUtils.UpdateCheck)");
    I --> J("Initialize Update Pipeline Data <br/> Targets: Config, App, Miniservers");
    J --> K_ExecutePipeline["Execute Update Pipeline <br/> (LoxoneUtils.WorkflowSteps)"];

    K_ExecutePipeline --> S1;

    subgraph pipeline_steps [Update Pipeline Steps]
        S1("S1: Download Loxone Config <br/> Get .zip; Verify CRC, <br/> filesize, code signing cert <br/> (uses -EnableCRC) <br/> (LoxoneUtils.Network, LoxoneUtils.Utility)") --> S2("S2: Extract Loxone Config <br/> Unzip archive <br/> (LoxoneUtils.Installation)");
        S2 --> S3("S3: Install Loxone Config <br/> Run with -InstallMode <br/> (LoxoneUtils.Installation)");
        S3 --> S4("S4: Download Loxone App <br/> Get .exe/.msi (if -UpdateLoxoneApp) <br/> Verify CRC, filesize, cert <br/> (uses -EnableCRC, -SkipCertCheck) <br/> (LoxoneUtils.Network)");
        S4 --> S5("S5: Install Loxone App <br/> Run with -InstallMode <br/> (LoxoneUtils.Installation)");
        S5 --> S6("S6: Check Miniserver Versions <br/> Compare installed Config ver. <br/> with MS firmware <br/> (LoxoneUtils.Miniserver)");
        S6 --> S7("S7: Update Miniservers <br/> Trigger if new Config ver. <br/> compatible and newer <br/> (LoxoneUtils.Miniserver)");
    end

    S7 --> L_Ops("Post-Pipeline Operations <br/> Error Handling, Logging, <br/> Notifications (LoxoneUtils.ErrorHandling, <br/> .Logging, .Toast)");
    L_Ops --> ZEnd["Exit (Workflow Complete)"];
```
## Features

*   **Orchestration (`UpdateLoxone.ps1`):**
    *   Manages the overall update process.
    *   Parses command-line parameters.
    *   Handles execution context, including re-launching as the current user if started as SYSTEM for the initial run.
    *   Supports task registration for automated execution.
*   **Modular Design (`LoxoneUtils`):** Utilizes a collection of specialized modules for various tasks:
    *   **`LoxoneUtils.WorkflowSteps`:** Defines and executes the individual steps of the update pipeline (Download Config, Install App, Update Miniservers, etc.).
    *   **`LoxoneUtils.UpdateCheck`:** Fetches the latest update information (versions for Config/App) from Loxone's official XML feed.
    *   **`LoxoneUtils.Network`:** Handles file downloads with progress indicators and verification.
    *   **`LoxoneUtils.Installation`:** Manages installer execution (silent/verysilent), version retrieval of installed software, finding installation paths, and ZIP file extraction.
    *   **`LoxoneUtils.Miniserver`:** Checks Miniserver versions and triggers updates on them.
    *   **`LoxoneUtils.Logging`:** Provides comprehensive logging with automatic rotation based on file count and age, thread-safe operations, and multiple log levels (INFO, WARN, ERROR, DEBUG).
    *   **`LoxoneUtils.ErrorHandling`:** Implements detailed error logging to aid in troubleshooting.
    *   **`LoxoneUtils.Toast`:** Delivers desktop toast notifications for status updates and errors using the `BurntToast` module. Recently optimized to reduce code size by ~50% and fixed auto-dismiss issue by using `Submit-BTNotification` with `Reminder` scenario, ensuring notifications remain visible during long operations.
    *   **`LoxoneUtils.Utility`:** Contains general helper functions for path manipulation, software signature checks, string and version formatting, CRC checksums, and registry interactions.
    *   **`LoxoneUtils.System`:** Manages system processes and Windows Scheduled Tasks.
    *   **`LoxoneUtils.RunAsUser`:** Facilitates running processes as the currently interactive user, primarily used for the initial re-launch from SYSTEM context.
*   **Automatic Update Checks:** Regularly checks `update.loxone.com` for new versions based on the selected channel.
*   **Silent Installation:** Installs Loxone Config and App updates silently.
*   **Miniserver Updates:** Can trigger updates on Loxone Miniservers listed in `UpdateLoxoneMSList.txt`.
*   **Channel Selection:** Allows choosing between Release, Beta, or Test update channels for Loxone Config and the Loxone App.
*   **CRC Checksum Verification:** Optionally verifies the CRC32 checksum of downloaded installers.
*   **Process Handling:** Optionally closes running Loxone Config instances before updating or skips updates if Loxone Config is running.
*   **Scheduled Task Integration:** Can create/update a Windows Scheduled Task for periodic execution.
*   **Debug Mode:** Offers verbose logging for troubleshooting.

## Installation

The UpdateLoxone tool can be installed using the MSI installer or manually:

### MSI Installation (Recommended)
1. Download the latest MSI installer from the [Releases](https://github.com/deafsquad/UpdateLoxone/releases) page
2. Run the MSI installer - it will install to `C:\Program Files (x86)\UpdateLoxone`
3. A Start Menu shortcut will be created for easy access
4. The installer supports proper upgrades - newer versions will automatically update existing installations

### Manual Installation
1. Download and extract the latest release ZIP to a location of your choice
2. Ensure all files remain in their original structure (especially the `LoxoneUtils` folder)
3. Run `UpdateLoxone.ps1` from PowerShell

## Prerequisites

*   **PowerShell:** Version 5.1 or higher.
*   **`BurntToast` Module:** Required for desktop notifications. The script may attempt to install it if missing and run interactively or by the scheduled task.
*   **Windows OS:** Designed for Windows environments.
*   **Administrator Privileges:** Required for software installation and scheduled task management.
*   **Internet Access:** Necessary for downloading updates and the `BurntToast` module.
*   **`LoxoneUtils` Modules:** The `LoxoneUtils` directory containing all required `.psm1` module files must be present in the same directory as `UpdateLoxone.ps1`.

## Script Files

*   **`UpdateLoxone.ps1`:** The main orchestration script with emoji status indicators (🔄, 🚀, ⬇️, 📦, ✓, 🔍, ⚠️, ✗).
*   **`LoxoneUtils/` (Directory):** Contains the suite of PowerShell modules (`.psm1` files) that provide the core functionalities:
    *   `LoxoneUtils.ErrorHandling.psm1`
    *   `LoxoneUtils.Installation.psm1`
    *   `LoxoneUtils.Logging.psm1` - Thread-safe logging with automatic rotation
    *   `LoxoneUtils.Miniserver.psm1`
    *   `LoxoneUtils.Network.psm1`
    *   `LoxoneUtils.psd1` (Module manifest)
    *   `LoxoneUtils.psm1` (Main module file that likely loads others or acts as a wrapper)
    *   `LoxoneUtils.RunAsUser.psm1`
    *   `LoxoneUtils.System.psm1`
    *   `LoxoneUtils.Toast.psm1` - Recently optimized (~50% smaller)
    *   `LoxoneUtils.UpdateCheck.psm1`
    *   `LoxoneUtils.Utility.psm1`
    *   `LoxoneUtils.WorkflowSteps.psm1`
    *   `LoxoneUtils.TestCoverage.psm1` - Test coverage analysis
    *   `LoxoneUtils.TestTracking.psm1` - Test assertion tracking
*   **`publish_new_release.ps1`:** Automated release script that creates MSI installers and manages GitHub releases.
*   **`tests/` (Directory):** Comprehensive test suite with 100% module coverage:
    *   `run-tests.ps1` - Main test runner with CI/CD support
    *   `Unit/`, `Integration/`, `System/` - Test categories
    *   39 test files covering all PowerShell modules

## Configuration Files

*(Place these files in the directory specified by `-ScriptSaveFolder`, which defaults to the script's own directory)*

*   **`UpdateLoxoneMSList.txt`:** (Optional) A text file containing connection details for Loxone Miniservers to be updated, one entry per line.
    *   Format: `http://username:password@ip-address-or-hostname` or `https://username:password@ip-address-or-hostname`.
    *   **Security Warning:** Passwords are stored in plain text. Ensure appropriate file permissions.
    *   If missing, Miniserver updates will be skipped.
*   **`UpdateLoxoneMSList.txt.example`:** An example file showing the format for `UpdateLoxoneMSList.txt`.
*   **Loxone Update XML:** The script fetches update information from `https://update.loxone.com/updatecheck.xml`.

## Parameters

*   `-Channel <String>`: (Optional) Specifies the update channel for Loxone Config. Options: `Release`, `Beta`, `Test`. Default might be `Test` or as defined in script.
*   `-DebugMode`: (Optional) Enables verbose debug logging.
*   `-EnableCRC`: (Optional) Enables CRC32 checksum verification of downloaded installers.
*   `-InstallMode <String>`: (Optional) Sets the installer mode for Loxone Config/App. Options: `silent`, `verysilent`.
*   `-CloseApplications`: (Optional) If set, forces running `LoxoneConfig.exe` instances to close before an update.
*   `-ScriptSaveFolder <String>`: (Optional) Directory to store logs, downloads, and the script itself (referenced by the scheduled task). Defaults to the script's execution directory.
*   `-MaxLogFileSizeMB <Int32>`: (Optional) Maximum size in MB for the main log file before rotation.
*   `-RegisterTask`: (Optional) If specified, the script will register/update the scheduled task and then exit.
*   `-SkipUpdateIfAnyProcessIsRunning`: (Optional) If set, the Loxone Config/App update will be skipped if `LoxoneConfig.exe` is detected running.
*   `-UpdateLoxoneApp`: (Optional) A switch to control whether the Loxone App should also be updated as part of the pipeline.
*   `-UpdateLoxoneAppChannel <String>`: (Optional) Specifies the update channel for the Loxone App if `-UpdateLoxoneApp` is used. Options: `Release`, `Beta`, `Test`.
*   `-SkipCertificateCheck`: (Optional) If set, bypasses SSL/TLS certificate validation for connections to Loxone Miniservers (e.g., for version checks or triggering updates). Use with caution, as this can be a security risk. This parameter does not affect SSL/TLS validation for downloading Config/App installers from Loxone's servers.

## Usage

1.  Ensure `UpdateLoxone.ps1` and the entire `LoxoneUtils` directory (with all its `.psm1` module files) are placed together in a stable final location (e.g., `C:\Scripts\UpdateLoxone`).
2.  (Optional) Create `UpdateLoxoneMSList.txt` in the `-ScriptSaveFolder` (defaults to script's directory) with your Miniserver details.
3.  To set up automated updates, run `UpdateLoxone.ps1` **once** interactively from its final location with the `-RegisterTask` parameter. It will request Administrator elevation if needed.
    ```powershell
    # Example: Register the task, use Release channel for Config
    .\UpdateLoxone.ps1 -RegisterTask -Channel Release
    ```
4.  This initial run (with `-RegisterTask`) creates/updates a scheduled task (typically named `LoxoneUpdateTask`) to run the script periodically as SYSTEM with highest privileges.
5.  Subsequent runs by the scheduled task will perform the update checks and installations silently based on the parameters baked into the task or defaults.

## Workflow Overview (Scheduled Task Execution)

1.  **Parameter Parsing & Context Initialization:** The script starts, parses any parameters passed by the task, and initializes its context (paths, logging, versions).
2.  **SYSTEM User Check (Initial Run Logic):** If running as SYSTEM and it's an initial invocation (not a self-relaunch), it may re-launch itself as the current interactive user to handle UI elements like `BurntToast` installations or initial prompts correctly. Subsequent operations by the task usually run fully as SYSTEM.
3.  **Import Modules:** Loads necessary functions from the `LoxoneUtils` modules.
4.  **Fetch Update Prerequisites:** Contacts `https://update.loxone.com/updatecheck.xml` to get the latest available versions for Loxone Config and App for the specified channels.
5.  **Initialize Pipeline Data:** Prepares information about update targets (Config, App, Miniservers).
6.  **Execute Update Pipeline (`LoxoneUtils.WorkflowSteps`):**
    *   **Download Loxone Config:** If an update is available.
    *   **Extract Loxone Config:** From the downloaded archive.
    *   **Install Loxone Config:** Silently.
    *   **Download Loxone App:** If an update is available and `-UpdateLoxoneApp` is enabled.
    *   **Install Loxone App:** Silently.
    *   **Check Miniserver Versions (`LoxoneUtils.Miniserver`):**
        *   Iterates through each Miniserver defined in `UpdateLoxoneMSList.txt`.
        *   Connects to the Miniserver's `/dev/cfg/version` endpoint to retrieve its current firmware version.
        *   Handles authentication using credentials from the `UpdateLoxoneMSList.txt` entry.
        *   Respects the `-SkipCertificateCheck` parameter for SSL/TLS certificate validation during this connection.
        *   Compares the Miniserver's current firmware version with the target Loxone Config version (typically the one just installed or the existing one if no Config update occurred).
        *   Miniservers with firmware older than the target Config version are marked as requiring an update.
    *   **Update Miniservers (`LoxoneUtils.Miniserver`, `LoxoneUtils.WorkflowSteps`):** For each Miniserver marked as needing an update:
        *   **`updatelevel` Validation:**
            *   The script connects to the Miniserver's `/dev/cfg/updatelevel` endpoint.
            *   It verifies that the Miniserver's own update channel setting (e.g., "Alpha", "Beta", "Release") aligns with the script's configured `-Channel` parameter (note: the script's "Test" channel corresponds to "Alpha" on the Miniserver).
            *   If a mismatch is detected (e.g., script is set to "Test" but Miniserver is on "Release"), the update for that specific Miniserver is aborted. An error message is logged, guiding the user to correct the Miniserver's `updatelevel` setting via a provided URL.
        *   **Trigger Update:**
            *   If the `updatelevel` validation passes, the script sends a request to the Miniserver's `/dev/sys/autoupdate` endpoint. This command instructs the Miniserver to start its firmware update process using the Loxone Config version present on the machine running the script.
        *   **Polling and Verification:**
            *   After triggering the update, the script begins polling the Miniserver's `/dev/cfg/version` endpoint.
            *   It monitors for signs of the update process, such as temporary unresponsiveness (as the Miniserver reboots) or an HTTP 503 status code (often indicating the Miniserver is busy with the update).
            *   Once the Miniserver becomes responsive again, the script retrieves the new firmware version.
            *   The update for that Miniserver is deemed successful if the newly reported firmware version matches the target Loxone Config version.
        *   All outcomes (success, failure, skipped due to `updatelevel` mismatch) are logged.
7.  **Error Handling & Logging:** Throughout the process, all actions, errors, and significant events are logged. `LoxoneUtils.ErrorHandling` captures detailed error information.
8.  **Toast Notifications:** `LoxoneUtils.Toast` sends notifications to the interactive user (if applicable) about the update status.
9.  **Log Rotation:** `LoxoneUtils.Logging` manages log file sizes and archives.
10. **Exit.**

## Notes

*   The script relies on specific Loxone web endpoints and behaviors which could change.
*   **Log File Location:** 
    *   When installed via MSI to Program Files: Logs are written to `%LOCALAPPDATA%\UpdateLoxone\Logs\`
    *   When run from other locations: Logs are written to `ScriptSaveFolder\Logs\` (defaults to script directory)
*   Check `UpdateLoxone_[username]_[timestamp].log` for detailed operational logs and troubleshooting.
*   Log files are automatically rotated when they exceed 10MB, with automatic cleanup of old logs.
*   Manage the scheduled task via Windows Task Scheduler (`taskschd.msc`).

## Testing

The project includes a comprehensive test suite with 100% module coverage, using Pester v5 framework.

*   **Test Runner:** `tests\run-tests.ps1` - Main test runner with multiple options
*   **Test Categories:**
    *   **Unit Tests:** Fast, isolated tests with no external dependencies
    *   **Integration Tests:** Tests that interact with network or file system
    *   **System Tests:** Tests requiring administrator privileges
*   **Usage:**
    ```powershell
    # Run unit tests (fast, ~2-3 min)
    .\tests\run-tests.ps1

    # Run all tests including integration and SYSTEM tests
    .\tests\run-tests.ps1 -TestType All

    # Run with detailed output
    .\tests\run-tests.ps1 -Detailed

    # Run with live progress notifications
    .\tests\run-tests.ps1 -LiveProgress

    # CI mode (no prompts, minimal output)
    .\tests\run-tests.ps1 -CI

    # Skip SYSTEM tests (which require admin)
    .\tests\run-tests.ps1 -SkipSystemTests
    ```
*   **Test Coverage:** The test suite includes:
    *   39 test files covering all 11 PowerShell modules
    *   Four test types per module: Simple, Working, Characterization, and Full tests
    *   Automated coverage analysis and reporting
    *   Test assertion tracking for coverage metrics
*   **CI/CD Integration:** Tests are automatically run before each release via `publish_new_release.ps1`

## Development

### Building and Releasing

The project uses an automated release process:

```powershell
# Create a new release (runs tests, creates MSI, generates manifests, creates GitHub release)
.\publish_new_release.ps1 -PackageIdentifier "deafsquad.UpdateLoxone"

# Dry run to see what would happen
.\publish_new_release.ps1 -PackageIdentifier "deafsquad.UpdateLoxone" -DryRun
```

The release script:
- Automatically increments version numbers
- Runs the full test suite (release fails if tests fail)
- Creates an MSI installer using PSMSI module
- Generates winget manifest files
- Creates a GitHub release with the MSI as an asset
- Supports dry runs for testing the release process

### Recent Improvements

- **MSI Installer:** Replaced ZIP packaging with proper MSI installer for winget compatibility
- **Smart Log Redirection:** Logs are automatically redirected to user profile when installed in Program Files
- **Toast Notification Fixes:** Fixed auto-dismiss issues and optimized module size by ~50%
- **Comprehensive Testing:** Added 100% module coverage with automated test suite
- **Dry Run Enhancements:** Auto-increment versions to avoid duplicate installations during testing