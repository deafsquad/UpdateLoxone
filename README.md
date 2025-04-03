# Loxone Auto Update Script (UpdateLoxone.ps1)

This PowerShell script automates the process of checking for, downloading, and installing updates for Loxone Config software. It can also trigger updates on configured Loxone Miniservers based on the installed Loxone Config version.

## Features

*   **Automatic Update Checks:** Regularly checks `update.loxone.com` for new versions based on selected channel (Release, Beta, Test).
*   **Silent Installation:** Installs Loxone Config updates silently using `/verysilent` or `/silent` modes.
*   **Miniserver Updates:** Can trigger updates on Loxone Miniservers listed in `UpdateLoxoneMSList.txt`. Checks Miniserver version against the *just installed/verified* Loxone Config version and initiates update if necessary. Includes reachability checks before and after update attempts.
*   **Interactive Miniserver Setup:** If run interactively and `UpdateLoxoneMSList.txt` is missing, prompts the user to configure the first Miniserver.
*   **Channel Selection:** Choose between Release, Beta, or Test update channels.
*   **CRC Checksum Verification:** Optionally verifies the CRC32 checksum of downloaded installers.
*   **Process Handling:** Optionally closes running Loxone Config instances before updating or skips updates if Loxone Config is running.
*   **Desktop Notifications:** Provides desktop notifications (using BurntToast module) for update status and errors to logged-in interactive users.
*   **Scheduled Task Integration:** Can automatically create/update a Windows Scheduled Task (`LoxoneUpdateTask`) to run the script periodically as the SYSTEM user with highest privileges.
*   **Robust Logging:** Creates detailed log files (`UpdateLoxone.log`) with automatic rotation (keeps the last 24 archives by default, named `UpdateLoxone_yyyyMMdd_HHmmss.log`). Log lines include Process ID and elevation status (e.g., `[PID:1234|Elevated:True]`).
*   **Error Handling:** Includes detailed error logging (command, line number, variables) and sends notifications on failure before exiting.
*   **Debug Mode:** Provides verbose logging for troubleshooting.
*   **Loxone Monitor Testing:** Includes a `-TestMonitor` mode to test starting the Loxone Monitor process and watching/moving its log files.

## Prerequisites

*   **PowerShell:** Version 5.1 or higher recommended.
*   **BurntToast Module:** Required for desktop notifications. If not installed, the script will attempt to install it for the *current user* when run interactively, or when sending a notification via the scheduled task method (requires internet access and permissions). Run `Install-Module BurntToast -Scope CurrentUser` if needed for interactive use or ensure it's available for the SYSTEM user if relying on task-based notifications.
*   **Administrator Privileges:** Required to install software and manage scheduled tasks. The script attempts to self-elevate if not run as admin during initial setup.
*   **Internet Access:** Required to check for updates, download installers, and potentially install BurntToast.
*   **Network Access:** Required to communicate with Loxone Miniservers for version checks and updates.

## Script Files

*   **`UpdateLoxone.ps1`:** The main script to be executed or scheduled. Handles parameter parsing, update checks, downloads, installation, and calls functions from the utility module.
*   **`UpdateLoxoneUtils.psm1`:** A PowerShell module containing all the helper functions used by the main script (logging, version checks, network operations, task management, etc.). This file must be present in the same directory as `UpdateLoxone.ps1`.
*   **`Run-UpdateLoxoneTests.ps1`:** A script for testing the functions within `UpdateLoxoneUtils.psm1`. See "Testing" section below.

## Configuration Files

*(Place these files in the same directory as the scripts)*

*   **`UpdateLoxoneMSList.txt`:** (Optional) A text file containing the connection URLs for Loxone Miniservers to be updated, one per line.
    *   Format: `http://username:password@ip-address-or-hostname` or `https://username:password@ip-address-or-hostname`.
    *   **Security Warning:** Passwords are stored in plain text. Use with caution.
    *   If this file is missing when the script runs interactively, you will be prompted to create it with the first entry. If missing when run via scheduled task, Miniserver updates will be skipped (logged as a warning).
*   **`UpdateLoxoneMSList.txt.example`:** An example file showing the format for `UpdateLoxoneMSList.txt`.
*   **`TrustedCertThumbprint.txt`:** (Optional) This file is currently **not used** by the script's signature verification logic. The script only performs a basic check if the downloaded installer has a valid Authenticode signature using `Get-AuthenticodeSignature`.

## Parameters

*   `-Channel`: (Optional) Update channel to check. Options: `Release`, `Beta`, `Test`. Default: `Test`.
*   `-DebugMode`: (Optional) Enable verbose debug logging to console and log file. Default: `$false`.
*   `-EnableCRC`: (Optional) Enable CRC32 checksum verification of downloaded Loxone Config installers. Default: `$true`.
*   `-InstallMode`: (Optional) Installer mode for Loxone Config. Options: `silent`, `verysilent`. Default: `verysilent`.
*   `-CloseApplications`: (Optional) Force close running `LoxoneConfig.exe` processes before attempting update. Default: `$false`.
*   `-ScriptSaveFolder`: (Optional) Directory to store logs, downloads, and potentially the script itself (used for scheduled task path). Default: The script's own directory.
*   `-MaxLogFileSizeMB`: (Optional) Maximum size in MB before the main log file (`UpdateLoxone.log`) is rotated. Default: `1`.
*   `-ScheduledTaskIntervalMinutes`: (Optional) Interval in minutes for the scheduled task recurrence. Default: `10`.
*   `-SkipUpdateIfAnyProcessIsRunning`: (Optional) Skip the Loxone Config update if `LoxoneConfig.exe` is detected running. Default: `$false`.
*   `-TestNotifications`: (Optional) Run in a mode that only tests sending start/end notifications. Default: `$false`.
*   `-MonitorLogWatchTimeoutMinutes`: (Optional) Timeout in minutes for watching Loxone Monitor logs (used only with `-TestMonitor`). Default: `240`.
*   `-TestMonitor`: (Optional) Run in a mode that tests starting the Loxone Monitor, watching its logs, and moving them. Default: `$false`.
*   `-MonitorSourceLogDirectory`: (Optional) Specify the source directory for Loxone Monitor logs when using `-TestMonitor`. If omitted, the script attempts to determine the correct path: if `loxonemonitor.exe` is already running, it assumes the log path based on whether the *script* is running as SYSTEM or a user (logging this assumption); if the monitor isn't running, it starts it interactively and watches the interactive user's Documents folder (`%USERPROFILE%\Documents\Loxone\Loxone Config\Monitor`). **Use this parameter to override the default if the automatic detection guesses incorrectly** (e.g., if the monitor was started by SYSTEM but the script is run interactively).


## Usage

1.  **Manually place** both the `UpdateLoxone.ps1` and `UpdateLoxoneUtils.psm1` scripts together in your desired final location (e.g., `C:\Scripts\UpdateLoxone`). This location must contain both files and should be stable, as the scheduled task will reference the `.ps1` file here.
2.  (Optional) Create `UpdateLoxoneMSList.txt` in the same directory with your Miniserver details, or wait for the script to prompt you on the first interactive run.
3.  Run the `UpdateLoxone.ps1` script **once** interactively *from its final location* to set up the scheduled task. You can start it from a regular PowerShell prompt; it will request Administrator elevation via a UAC prompt if needed:
    ```powershell
    # Example (run from C:\Scripts\UpdateLoxone):
    .\UpdateLoxone.ps1 -Channel Release -CloseApplications $true
    ```
4.  During this first interactive run, the script will attempt self-elevation if needed (to gain Administrator privileges) and then create/update a scheduled task named `LoxoneUpdateTask` pointing to the script's location (determined by `-ScriptSaveFolder`, which defaults to the script's own directory).
5.  This task runs as the `SYSTEM` user with highest privileges, triggered initially and then repeating every `-ScheduledTaskIntervalMinutes` (default 10). Task registration/update is skipped on subsequent non-interactive runs (i.e., when run by the scheduler itself).
6.  Subsequent runs performed by the scheduled task will handle the update checks and installations silently.

## Workflow Overview (Scheduled Task)

1.  **Log Rotation:** If running as the initial (non-elevated) instance, checks and rotates the main log file if size exceeds limit. Rotation is skipped if running as the self-elevated instance to maintain log continuity.
2.  **Installation Check:** Determines the path and version of the currently installed Loxone Config.
3.  **Process Check:** If `-SkipUpdateIfAnyProcessIsRunning` is `$true`, checks if `LoxoneConfig.exe` is running and exits if it is.
4.  **Update Check:** Downloads `updatecheck.xml` from Loxone.
5.  **Version Comparison:** Compares the installed version (if any) with the version available for the specified `-Channel`.
6.  **Loxone Config Update (if needed):**
    *   Downloads the installer ZIP.
    *   Verifies file size and optionally CRC32 checksum.
    *   Extracts the `.exe` installer.
    *   Verifies if the installer has a valid Authenticode digital signature (basic check using `Get-AuthenticodeSignature`; does not check against a trusted thumbprint).
    *   Runs the installer silently (`-InstallMode`).
7.  **Miniserver Update Process (runs after Config update or if Config was already up-to-date):**
    *   Calls `Update-MS` function.
    *   Checks if `UpdateLoxoneMSList.txt` exists. If not, logs a warning and skips Miniserver updates for this run.
    *   If file exists, iterates through each URL:
        *   Checks the Miniserver's current version via `/dev/cfg/version`.
        *   Compares with the target Loxone Config version (`$updateVersion`).
        *   If Miniserver needs update:
            *   Triggers the update (likely via `/sps/log/<clientIP>` endpoint).
            *   Waits for the Miniserver to become unreachable (ping fails).
            *   Waits for the Miniserver to become reachable again (ping succeeds).
            *   Waits an additional 60 seconds.
            *   Repeatedly checks the Miniserver version for up to 8 minutes until it matches the target version. Logs errors if it fails or times out.
8.  **Notifications:** Sends success/failure notifications to logged-in users.
9.  **Exit.**

## Notes

*   The script relies on specific Loxone web endpoints (`update.loxone.com`, `/dev/cfg/version`, `/sps/log/...`) which could change in the future.
*   Error handling attempts to log details and notify users, but complex failures might still occur. Check `UpdateLoxone.log` for details.
*   Managing the scheduled task (e.g., changing interval, disabling) can be done via the Windows Task Scheduler (`taskschd.msc`). Find the task named `LoxoneUpdateTask`.

## Testing

A separate script, `Run-UpdateLoxoneTests.ps1`, is provided to test the core functions within the `UpdateLoxoneUtils.psm1` module.

*   **Purpose:** Verify individual function logic in different contexts (normal, simulated task, elevated).
*   **Usage:**
    ```powershell
    # Run all tests (attempts elevation by default)
    .\Run-UpdateLoxoneTests.ps1

    # Run only tests in the 'Logging' category
    .\Run-UpdateLoxoneTests.ps1 -TestName Logging

    # Run only a specific function test
    .\Run-UpdateLoxoneTests.ps1 -TestName Get-RedactedPassword

    # Run all tests but skip the elevated run attempt
    .\Run-UpdateLoxoneTests.ps1 -SkipElevation
    ```
*   The script runs tests non-elevated first, then attempts to re-launch itself elevated (unless `-SkipElevation` is used) to run tests requiring admin rights and re-run others in an elevated context.
*   A combined summary is displayed in the initial console window after all runs complete.