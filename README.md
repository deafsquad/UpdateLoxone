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
*   **Robust Logging:** Creates detailed log files (`UpdateLoxone.log`) with automatic rotation (keeps the last 24 archives by default, named `UpdateLoxone_yyyyMMdd_HHmmss.log`).
*   **Error Handling:** Includes detailed error logging (command, line number, variables) and sends notifications on failure before exiting.
*   **Debug Mode:** Provides verbose logging for troubleshooting.
*   **Loxone Monitor Testing:** Includes a `-TestMonitor` mode to test starting the Loxone Monitor process and watching/moving its log files.

## Prerequisites

*   **PowerShell:** Version 5.1 or higher recommended.
*   **BurntToast Module:** Required for desktop notifications. If not installed, the script will attempt to install it for the *current user* when run interactively, or when sending a notification via the scheduled task method (requires internet access and permissions). Run `Install-Module BurntToast -Scope CurrentUser` if needed for interactive use or ensure it's available for the SYSTEM user if relying on task-based notifications.
*   **Administrator Privileges:** Required to install software and manage scheduled tasks. The script attempts to self-elevate if not run as admin during initial setup.
*   **Internet Access:** Required to check for updates, download installers, and potentially install BurntToast.
*   **Network Access:** Required to communicate with Loxone Miniservers for version checks and updates.

## Configuration Files

*(Place these files in the same directory as the script)*

*   **`UpdateLoxoneMSList.txt`:** (Optional) A text file containing the connection URLs for Loxone Miniservers to be updated, one per line.
    *   Format: `http://username:password@ip-address-or-hostname` or `https://username:password@ip-address-or-hostname`.
    *   **Security Warning:** Passwords are stored in plain text. Use with caution.
    *   If this file is missing when the script runs interactively, you will be prompted to create it with the first entry. If missing when run via scheduled task, Miniserver updates will be skipped (logged as a warning).
*   **`UpdateLoxoneMSList.txt.example`:** An example file showing the format for `UpdateLoxoneMSList.txt`.
*   **`TrustedCertThumbprint.txt`:** (Optional) Intended for verifying executable signatures (currently placeholder logic in the script).

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
*   `-MonitorSourceLogDirectory`: (Optional) Specify the source directory for Loxone Monitor logs when using `-TestMonitor`. If omitted, defaults to the SYSTEM profile's Documents folder when run as SYSTEM, or the current user's Documents folder otherwise.


## Usage

1.  Place the `UpdateLoxone.ps1` script in a desired location (e.g., `C:\Scripts\UpdateLoxone`). Ensure this location is stable as the scheduled task will reference it.
2.  (Optional) Create `UpdateLoxoneMSList.txt` in the same directory with your Miniserver details, or wait for the script to prompt you on the first interactive run.
3.  Run the script **once** from an **Administrator PowerShell prompt** to set up the scheduled task:
    ```powershell
    # Example: Set up task using Release channel, closing apps
    .\UpdateLoxone.ps1 -Channel Release -CloseApplications $true
    ```
4.  The script will copy itself to the `-ScriptSaveFolder` (if different), attempt self-elevation if needed, and then create/update a scheduled task named `LoxoneUpdateTask`.
5.  This task runs as the `SYSTEM` user with highest privileges, triggered initially and then repeating every `-ScheduledTaskIntervalMinutes` (default 10).
6.  Subsequent runs performed by the scheduled task will handle the update checks and installations silently.

## Workflow Overview (Scheduled Task)

1.  **Log Rotation:** Checks and rotates the main log file if size exceeds limit.
2.  **Installation Check:** Determines the path and version of the currently installed Loxone Config.
3.  **Process Check:** If `-SkipUpdateIfAnyProcessIsRunning` is `$true`, checks if `LoxoneConfig.exe` is running and exits if it is.
4.  **Update Check:** Downloads `updatecheck.xml` from Loxone.
5.  **Version Comparison:** Compares the installed version (if any) with the version available for the specified `-Channel`.
6.  **Loxone Config Update (if needed):**
    *   Downloads the installer ZIP.
    *   Verifies file size and optionally CRC32 checksum.
    *   Extracts the `.exe` installer.
    *   Verifies the installer's digital signature (basic check).
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