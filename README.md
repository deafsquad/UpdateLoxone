# Loxone Auto Update Script (UpdateLoxone.ps1)

This PowerShell script automates the process of checking for, downloading, and installing updates for Loxone Config software. It can also trigger updates on configured Loxone Miniservers.

## Features

*   **Automatic Update Checks:** Regularly checks `update.loxone.com` for new versions based on selected channel (Release, Beta, Test).
*   **Silent Installation:** Installs Loxone Config updates silently using `/verysilent` or `/silent` modes.
*   **Miniserver Updates:** Can trigger updates on Loxone Miniservers listed in `UpdateLoxoneMSList.txt`.
*   **Channel Selection:** Choose between Release, Beta, or Test update channels.
*   **CRC Checksum Verification:** Optionally verifies the CRC32 checksum of downloaded installers.
*   **Process Handling:** Optionally closes running Loxone Config instances before updating or skips updates if Loxone Config is running.
*   **Desktop Notifications:** Provides desktop notifications (using BurntToast module) for update status and errors.
*   **Scheduled Task Integration:** Can automatically create/update a Windows Scheduled Task to run the script periodically.
*   **Robust Logging:** Creates detailed log files (`UpdateLoxone.log`) with rotation.
*   **Error Handling:** Includes error handling and reporting.
*   **Debug Mode:** Provides verbose logging for troubleshooting.

## Prerequisites

*   **PowerShell:** Version 5.1 or higher recommended.
*   **BurntToast Module:** Required for desktop notifications. If not installed, the script will attempt to install it for the current user (requires internet access and permissions). Run `Install-Module BurntToast -Scope CurrentUser` if needed.
*   **Administrator Privileges:** Required to install software and manage scheduled tasks. The script attempts to self-elevate if not run as admin.
*   **Internet Access:** Required to check for updates, download installers, and potentially install BurntToast.

## Configuration Files

*(Place these files in the same directory as the script)*

*   **`UpdateLoxoneMSList.txt`:** (Optional) A text file containing the connection URLs for Loxone Miniservers to be updated, one per line. Format: `http://username:password@ip-address` or `https://username:password@ip-address`.
*   **`TrustedCertThumbprint.txt`:** (Optional) Used for verifying executable signatures (currently placeholder logic).

## Parameters

*   `-Channel`: (Optional) Update channel to check. Options: `Release`, `Beta`, `Test`. Default: `Test`.
*   `-DebugMode`: (Optional) Enable verbose debug logging. Default: `$false`.
*   `-EnableCRC`: (Optional) Enable CRC32 checksum verification of downloaded files. Default: `$true`.
*   `-InstallMode`: (Optional) Installer mode. Options: `silent`, `verysilent`. Default: `verysilent`.
*   `-CloseApplications`: (Optional) Force close running Loxone Config processes before update. Default: `$false`.
*   `-ScriptSaveFolder`: (Optional) Directory to store logs, downloads, and potentially the script itself. Default: The script's own directory.
*   `-MaxLogFileSizeMB`: (Optional) Maximum size in MB before log file rotation. Default: `1`.
*   `-ScheduledTaskIntervalMinutes`: (Optional) Interval for the scheduled task recurrence. Default: `10`.
*   `-SkipUpdateIfAnyProcessIsRunning`: (Optional) Skip the update if `LoxoneConfig.exe` is detected running. Default: `$false`.
*   `-TestNotifications`: (Optional) Run in a mode that only tests sending notifications. Default: `$false`.
*   `-MonitorLogWatchTimeoutMinutes`: (Optional) Timeout for watching Loxone Monitor logs (used with `-TestMonitor`). Default: `240`.
*   `-TestMonitor`: (Optional) Run in a mode that tests starting the Loxone Monitor and watching its logs. Default: `$false`.

## Usage

1.  Place the `UpdateLoxone.ps1` script in a desired location (e.g., `C:\Scripts\UpdateLoxone`).
2.  (Optional) Create `UpdateLoxoneMSList.txt` in the same directory with your Miniserver details.
3.  Run the script from an **Administrator PowerShell prompt**:
    ```powershell
    .\UpdateLoxone.ps1 -Channel Release -CloseApplications $true
    ```
4.  The first time it runs with admin rights, it should create a scheduled task named `LoxoneUpdateTask` to run automatically every 10 minutes (or the interval specified by `-ScheduledTaskIntervalMinutes`) as the SYSTEM user. Subsequent runs via the task will perform the update checks.

## Notes

*   The script attempts to self-elevate to Administrator if not run with sufficient privileges.
*   Log files are stored in the script's directory (`UpdateLoxone.log`) and rotated automatically.
*   Miniserver update logic includes checks to ensure the Miniserver is reachable before and after the update attempt.