# Consolidated Root Module Script File for LoxoneUtils
# Contains all functions previously in separate .psm1 files.
# The manifest (LoxoneUtils.psd1) points to this file as the RootModule
# and handles all exports via FunctionsToExport.

# Dot-source utility functions to make them available within the module scope
# . "$PSScriptRoot\LoxoneUtils.Utility.psm1" # Commented out for diagnostics

# --- Script-Scoped Variables ---

# Mutex is now handled solely within LoxoneUtils.Logging.psm1
$script:CallStack = [System.Collections.Generic.Stack[object]]::new()
# Re-entry guard flag for WriteLog (from Logging.psm1)
$script:InsideWriteLog = $false

# Persistent Toast Notification State (from Toast.psm1)
$script:PersistentToastId = "LoxoneUpdateStatusToast"
$script:PersistentToastData = @{ StatusText = "Initializing..."; ProgressValue = 0 } # Ensure ProgressValue is initialized
$script:PersistentToastInitialized = $false

# Flag for Ctrl+C handling (from Network.psm1 - needed by download functions)
$script:terminateRequested = $false

# --- End of Script-Scoped Variables ---

# All function definitions have been removed from this file.
# They should exist in their respective individual .psm1 files.
# This file now only serves to initialize shared script-scoped variables.