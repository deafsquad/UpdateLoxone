#Requires -Modules LoxoneUtils.Logging, LoxoneUtils.System, LoxoneUtils.UpdateCheck, LoxoneUtils.Utility, LoxoneUtils.Toast, LoxoneUtils.RunAsUser, LoxoneUtils.Installation

# Script-level variable to store step definitions for Get-StepWeight
$script:WorkflowStepDefinitions = @()

function Get-StepWeight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$StepID
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    Write-Log -Message "($FunctionName) Attempting to get weight for StepID: '$StepID'" -Level DEBUG

    if ($null -eq $script:WorkflowStepDefinitions -or $script:WorkflowStepDefinitions.Count -eq 0) {
        Write-Log -Message "($FunctionName) WorkflowStepDefinitions is not initialized or empty. Cannot get weight for StepID '$StepID'." -Level WARN
        return 0
    }

    $stepDefinition = $script:WorkflowStepDefinitions | Where-Object { $_.ID -eq $StepID } | Select-Object -First 1
    if ($stepDefinition) {
        Write-Log -Message "($FunctionName) Found weight '$($stepDefinition.Weight)' for StepID '$StepID'." -Level DEBUG
        return $stepDefinition.Weight
    } else {
        Write-Log -Message "($FunctionName) StepID '$StepID' not found in WorkflowStepDefinitions. Returning weight 0." -Level WARN
        return 0
    }
}

function Initialize-ScriptWorkflow {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$BoundParameters,

        [Parameter(Mandatory=$true)]
        [string]$PSScriptRoot, # Should be the directory of UpdateLoxone.ps1

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.InvocationInfo]$MyInvocation # From UpdateLoxone.ps1
    )

    $FunctionName = $MyInvocation.MyCommand.Name
    Write-Host "INFO: ($FunctionName) Starting initialization..." -ForegroundColor Cyan

    $scriptContext = [pscustomobject]@{
        Succeeded                       = $true
        Reason                          = ""
        Error                           = $null
        Component                       = "Initialization"
        ScriptSaveFolder                = $null
        LogFile                         = $null
        LogDir                          = $null
        IsAdminRun                      = $false
        IsElevatedInstance              = $false # Will be set by IsAdminRun
        IsInteractive                   = $false
        IsRunningAsSystem               = $false
        IsSelfInvokedForUpdateCheck     = $false # To be determined
        InitialInstalledConfigVersion   = ""
        InstalledConfigExePath          = $null
        InitialLoxoneAppDetails         = $null
        DownloadDir                     = $null
        MSListPath                      = $null
        Constants                       = @{}
        TaskName                        = "LoxoneUpdateTask"
        LoxoneIconPath                  = $null
        # Parameters passed from the main script
        Params                          = $BoundParameters
        MyScriptRoot                    = $PSScriptRoot # Directory of UpdateLoxone.ps1
        # Derived paths/values
        LoxoneUtilsModulePath           = (Get-Module LoxoneUtils).Path # Path to LoxoneUtils.psd1
        SystemCanLog                    = $false # Flag to track if Write-Log is usable by SYSTEM context for its specific logs
    }

    # --- Debug Preference ---
    if ($scriptContext.Params.DebugMode) {
        $Global:DebugPreference = 'Continue'
        Write-Host "INFO: ($FunctionName) DebugMode specified by main script, setting Global:DebugPreference = 'Continue'" -ForegroundColor Green
    } else {
        $Global:DebugPreference = 'SilentlyContinue'
        Write-Host "INFO: ($FunctionName) DebugMode NOT specified by main script, setting Global:DebugPreference = 'SilentlyContinue'" -ForegroundColor Green
    }

    # --- Script Save Folder ---
    # First, check if we're running from Program Files (always check this, regardless of parameter)
    $isInProgramFiles = $false
    if ($scriptContext.MyScriptRoot) {
        $scriptRoot = $scriptContext.MyScriptRoot
        
        $programFilesPaths = @(
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)},
            "$env:SystemDrive\Program Files",
            "$env:SystemDrive\Program Files (x86)"
        )
        
        foreach ($pfPath in $programFilesPaths) {
            if ($pfPath -and $scriptRoot.StartsWith($pfPath, [StringComparison]::OrdinalIgnoreCase)) {
                $isInProgramFiles = $true
                Write-Host "INFO: ($FunctionName) Script is running from Program Files: '$scriptRoot'" -ForegroundColor Yellow
                break
            }
        }
    }
    
    # Check if ScriptSaveFolder parameter was provided
    $tempScriptSaveFolder = if ($scriptContext.Params.ContainsKey('ScriptSaveFolder')) { 
        $scriptContext.Params.ScriptSaveFolder 
    } else { 
        $null 
    }
    
    if ([string]::IsNullOrWhiteSpace($tempScriptSaveFolder)) {
        # No parameter provided, determine default
        if ($isInProgramFiles) {
            # Always redirect to user's local app data when in Program Files
            $scriptContext.ScriptSaveFolder = Join-Path -Path $env:LOCALAPPDATA -ChildPath "UpdateLoxone"
            Write-Host "INFO: ($FunctionName) Script is in Program Files. Logs will be saved to user profile." -ForegroundColor Cyan
        } elseif ($scriptContext.MyScriptRoot) { 
            $scriptContext.ScriptSaveFolder = $scriptContext.MyScriptRoot 
        } else { 
            $scriptContext.ScriptSaveFolder = Join-Path -Path $env:LOCALAPPDATA -ChildPath "UpdateLoxone" 
        }
    } else {
        # Sanitize the provided ScriptSaveFolder to remove any leading/trailing quotes (single or double)
        $cleanedScriptSaveFolder = $tempScriptSaveFolder
        Write-Host "INFO: ($FunctionName) [PathCleaning] Original path: '$tempScriptSaveFolder'" -ForegroundColor Cyan
        
        # Remove single quotes
        $singleQuoteRemovalCount = 0
        while ($cleanedScriptSaveFolder.Length -ge 2 -and $cleanedScriptSaveFolder.StartsWith("'") -and $cleanedScriptSaveFolder.EndsWith("'")) {
            $cleanedScriptSaveFolder = $cleanedScriptSaveFolder.Substring(1, $cleanedScriptSaveFolder.Length - 2)
            $singleQuoteRemovalCount++
            Write-Host "INFO: ($FunctionName) [PathCleaning] Removed single quotes (pass $singleQuoteRemovalCount): '$cleanedScriptSaveFolder'" -ForegroundColor Cyan
        }
        
        # Remove double quotes  
        $doubleQuoteRemovalCount = 0
        while ($cleanedScriptSaveFolder.Length -ge 2 -and $cleanedScriptSaveFolder.StartsWith('"') -and $cleanedScriptSaveFolder.EndsWith('"')) {
            $cleanedScriptSaveFolder = $cleanedScriptSaveFolder.Substring(1, $cleanedScriptSaveFolder.Length - 2)
            $doubleQuoteRemovalCount++
            Write-Host "INFO: ($FunctionName) [PathCleaning] Removed double quotes (pass $doubleQuoteRemovalCount): '$cleanedScriptSaveFolder'" -ForegroundColor Cyan
        }
        
        if ($singleQuoteRemovalCount -eq 0 -and $doubleQuoteRemovalCount -eq 0) {
            Write-Host "INFO: ($FunctionName) [PathCleaning] No quotes found - path unchanged" -ForegroundColor Cyan
        } else {
            Write-Host "INFO: ($FunctionName) [PathCleaning] Final cleaned path: '$cleanedScriptSaveFolder'" -ForegroundColor Green
        }
        $scriptContext.ScriptSaveFolder = $cleanedScriptSaveFolder
        
        # Always redirect logs when running from Program Files to avoid permission issues
        if ($isInProgramFiles) {
            Write-Host "INFO: ($FunctionName) Script is in Program Files. Redirecting logs to user profile." -ForegroundColor Yellow
            $scriptContext.ScriptSaveFolder = Join-Path -Path $env:LOCALAPPDATA -ChildPath "UpdateLoxone"
            Write-Host "INFO: ($FunctionName) Logs will be saved to: '$($scriptContext.ScriptSaveFolder)'" -ForegroundColor Cyan
        }
    }
    Write-Host "INFO: ($FunctionName) ScriptSaveFolder set to: '$($scriptContext.ScriptSaveFolder)'" -ForegroundColor Cyan

    # --- Log Directory and File ---
    $scriptContext.LogDir = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "Logs"
    if (-not (Test-Path -Path $scriptContext.LogDir -PathType Container)) {
        Write-Host "INFO: ($FunctionName) Log directory '$($scriptContext.LogDir)' not found. Creating..." -ForegroundColor Cyan
        try { New-Item -Path $scriptContext.LogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
        catch {
            $scriptContext.Succeeded = $false; $scriptContext.Reason = "CreateLogDirFailed"; $scriptContext.Error = $_
            Write-Error "FATAL: ($FunctionName) Failed to create log directory '$($scriptContext.LogDir)'. Error: $($_.Exception.Message)"; return $scriptContext
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($scriptContext.Params.PassedLogFile)) {
        Write-Host "INFO: ($FunctionName) Using passed log file path: '$($scriptContext.Params.PassedLogFile)'" -ForegroundColor Cyan
        $PassedLogDir = Split-Path -Path $scriptContext.Params.PassedLogFile -Parent
        if (-not (Test-Path -Path $PassedLogDir -PathType Container)) {
            Write-Host "WARN: ($FunctionName) Directory for passed log file '$PassedLogDir' not found. Creating..." -ForegroundColor Yellow
            try { New-Item -Path $PassedLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            catch {
                $scriptContext.Succeeded = $false; $scriptContext.Reason = "CreatePassedLogDirFailed"; $scriptContext.Error = $_
                Write-Error "FATAL: ($FunctionName) Failed to create directory for passed log file '$PassedLogDir'. Error: $($_.Exception.Message)"; return $scriptContext
            }
        }
        $global:LogFile = $scriptContext.Params.PassedLogFile
    } else {
        Write-Host "INFO: ($FunctionName) No log file passed. Generating new log file name." -ForegroundColor Cyan
        $userNameForFile = (([Security.Principal.WindowsIdentity]::GetCurrent()).Name -split '\\')[-1] -replace '[\\:]', '_'
        
        # Create timestamp-based log file name with counter to ensure uniqueness
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseLogName = "UpdateLoxone_${userNameForFile}_${timestamp}.log"
        
        # Check if file already exists and add counter if needed
        $counter = 0
        $proposedLogName = $baseLogName
        while (Test-Path (Join-Path -Path $scriptContext.LogDir -ChildPath $proposedLogName)) {
            $counter++
            $proposedLogName = "UpdateLoxone_${userNameForFile}_${timestamp}_${counter}.log"
        }
        $baseLogName = $proposedLogName
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
        $regexInvalidChars = "[{0}]" -f [RegEx]::Escape($invalidChars)
        $sanitizedLogName = $baseLogName -replace $regexInvalidChars, '_'
        $global:LogFile = Join-Path -Path $scriptContext.LogDir -ChildPath $sanitizedLogName
    }
    $scriptContext.LogFile = $global:LogFile
    Write-Host "INFO: ($FunctionName) Global LogFile path set to '$($global:LogFile)'. Write-Log (if module loaded) will use this." -ForegroundColor Cyan

    # --- Crucial Check: Is Write-Log available? ---
    # This function is part of LoxoneUtils. The main script (UpdateLoxone.ps1) should have already run `Import-Module LoxoneUtils -Force`.
    # If Write-Log isn't available here, something is fundamentally wrong with the module load.
    if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        $errMsg = "CRITICAL ERROR: ($FunctionName) Write-Log command is NOT available. LoxoneUtils module (or its Logging component) did not load correctly. Script cannot continue."
        Write-Host $errMsg -ForegroundColor Red
        if ($global:LogFile) { Add-Content -Path $global:LogFile -Value "$(Get-Date -Format 'u') $errMsg" } # Fallback log attempt
        $scriptContext.Succeeded = $false; $scriptContext.Reason = "WriteLogUnavailable"; $scriptContext.Error = "Write-Log command missing after LoxoneUtils module import attempt by the main script."
        return $scriptContext # Critical failure
    }
    Write-Log -Message "($FunctionName) Initial log setup complete. Write-Log is available." -Level INFO

    # --- SYSTEM Context Handling ---
    $scriptContext.IsRunningAsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
    Write-Log -Message "($FunctionName) Running as SYSTEM: $($scriptContext.IsRunningAsSystem)" -Level DEBUG

    # If running as SYSTEM for the first time (no PassedLogFile), signal main script to re-launch.
    # The main script (UpdateLoxone.ps1) will handle the actual re-launch mechanics.
    if ($scriptContext.IsRunningAsSystem -and [string]::IsNullOrWhiteSpace($scriptContext.Params.PassedLogFile)) {
        Write-Log -Message "($FunctionName) Script is running as SYSTEM (initial invocation). Signaling main script to re-launch as user." -Level INFO
        $scriptContext.Succeeded = $true # Initialization succeeded enough to determine this.
        $scriptContext.Reason = "SystemRelaunchRequired"
        # Log rotation for the SYSTEM log will be handled by the re-launched user session script,
        # as it inherits the log file path.
        Write-Log -Message "($FunctionName) SYSTEM context: Skipping log rotation before signaling re-launch. User session will handle it." -Level DEBUG
        return $scriptContext # Exit this function, main script will handle re-launch and exit.
    }
    # If it's SYSTEM context but with PassedLogFile, it means it's the very brief execution of the *re-launched* script
    # when it was started by SYSTEM for task registration, which then re-invokes itself as user.
    # This scenario is complex; the original script's logic for SYSTEM -> User -> Elevated User (for task) needs careful mapping.
    # For now, if it's SYSTEM + PassedLogFile, we assume it's a transient state and proceed with limited init.

    # --- Admin Status ---
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        $scriptContext.IsAdminRun = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $scriptContext.IsElevatedInstance = $scriptContext.IsAdminRun
        $global:IsElevatedInstance = $scriptContext.IsAdminRun # For other functions expecting global
    } catch {
        Write-Log -Message "($FunctionName) Could not determine administrator status. Assuming non-admin. Error: $($_.Exception.Message)" -Level WARN
        $scriptContext.IsAdminRun = $false; $scriptContext.IsElevatedInstance = $false; $global:IsElevatedInstance = $false
    }
    Write-Log -Message "($FunctionName) Running as Admin: $($scriptContext.IsAdminRun)" -Level DEBUG

    # --- Interactivity & Self-Invocation ---
    # $IsDirectPathInvocation = $MyInvocation.InvocationName -match '^[A-Za-z]:\\' -or $MyInvocation.InvocationName -match '^\\\\' # Unused variable
    
    # Improved interactive detection that accounts for scheduled tasks
    $isConsoleHost = ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Windows PowerShell ISE Host' -or $Host.Name -eq 'Visual Studio Code Host')
    $isUserInteractive = [Environment]::UserInteractive
    $isScheduledTask = $false
    
    # Check if running as scheduled task by looking at parent process and other indicators
    try {
        # Method 1: Check parent process (optimized with faster WMI alternative)
        Write-Log -Message "($FunctionName) Checking parent process for scheduled task detection..." -Level DEBUG
        
        # Performance optimization: Use Get-Process instead of Get-CimInstance for speed
        try {
            $currentProcess = Get-Process -Id $PID -ErrorAction Stop
            $parentProcessId = $currentProcess.Parent.Id
            Write-Log -Message "($FunctionName) Found parent process ID: $parentProcessId" -Level DEBUG
            
            if ($parentProcessId) {
                $parentProcess = Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue
                if ($parentProcess) {
                    Write-Log -Message "($FunctionName) Parent process: $($parentProcess.Name) (PID: $parentProcessId)" -Level DEBUG
                    # svchost.exe as parent often indicates Task Scheduler
                    if ($parentProcess.Name -eq 'svchost') {
                        $isScheduledTask = $true
                        Write-Log -Message "($FunctionName) Detected running under Task Scheduler (parent: svchost)" -Level DEBUG
                    }
                    # taskeng.exe is the Task Scheduler engine
                    elseif ($parentProcess.Name -eq 'taskeng') {
                        $isScheduledTask = $true
                        Write-Log -Message "($FunctionName) Detected running under Task Scheduler (parent: taskeng)" -Level DEBUG
                    }
                }
            }
        } catch {
            # Fallback to slower CIM query only if Get-Process fails
            Write-Log -Message "($FunctionName) Get-Process failed, falling back to CIM query: $($_.Exception.Message)" -Level DEBUG
            $parentProcessId = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID").ParentProcessId
            if ($parentProcessId) {
                $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $parentProcessId" -ErrorAction SilentlyContinue
                if ($parentProcess) {
                    Write-Log -Message "($FunctionName) Parent process (CIM): $($parentProcess.Name) (PID: $parentProcessId)" -Level DEBUG
                    # svchost.exe as parent often indicates Task Scheduler
                    if ($parentProcess.Name -eq 'svchost.exe') {
                        $isScheduledTask = $true
                        Write-Log -Message "($FunctionName) Detected running under Task Scheduler (parent: svchost.exe)" -Level DEBUG
                    }
                    # taskeng.exe is the Task Scheduler engine
                    elseif ($parentProcess.Name -eq 'taskeng.exe') {
                        $isScheduledTask = $true
                        Write-Log -Message "($FunctionName) Detected running under Task Scheduler (parent: taskeng.exe)" -Level DEBUG
                    }
                }
            }
        }
        
        # Method 2: Check if we have a console window
        # Scheduled tasks typically run without a console window
        if (-not $isScheduledTask) {
            try {
                $consolePtr = [Console]::WindowHandle
                Write-Log -Message "($FunctionName) Console WindowHandle: $consolePtr" -Level DEBUG
                if ($consolePtr -eq [IntPtr]::Zero -or $consolePtr -eq 0) {
                    $isScheduledTask = $true
                    Write-Log -Message "($FunctionName) Detected non-interactive context (no console window)" -Level DEBUG
                }
            }
            catch {
                # If we can't access the console, likely non-interactive
                $isScheduledTask = $true
                Write-Log -Message "($FunctionName) Detected non-interactive context (console access failed: $_)" -Level DEBUG
            }
        }
        
        # Method 3: Check if standard input is redirected (common for scheduled tasks)
        if (-not $isScheduledTask) {
            try {
                if ([Console]::IsInputRedirected) {
                    $isScheduledTask = $true
                    Write-Log -Message "($FunctionName) Detected non-interactive context (input redirected)" -Level DEBUG
                }
                elseif ([Console]::IsOutputRedirected) {
                    $isScheduledTask = $true
                    Write-Log -Message "($FunctionName) Detected non-interactive context (output redirected)" -Level DEBUG
                }
                else {
                    # Additional check - if we're in a real console, we should be able to get window title
                    try {
                        $windowTitle = [Console]::Title
                        if ([string]::IsNullOrEmpty($windowTitle)) {
                            $isScheduledTask = $true
                            Write-Log -Message "($FunctionName) Detected non-interactive context (no console title)" -Level DEBUG
                        }
                    }
                    catch {
                        # Can't access console title - likely non-interactive
                        $isScheduledTask = $true
                        Write-Log -Message "($FunctionName) Detected non-interactive context (console title access failed)" -Level DEBUG
                    }
                }
            }
            catch {
                Write-Log -Message "($FunctionName) Error checking console redirection: $_" -Level DEBUG
            }
        }
    }
    catch {
        Write-Log -Message "($FunctionName) Error during scheduled task detection: $_" -Level DEBUG
    }
    
    # Interactive only if console host AND user interactive AND NOT scheduled task
    $scriptContext.IsInteractive = $isConsoleHost -and $isUserInteractive -and (-not $isScheduledTask)
    
    Write-Log -Message "($FunctionName) IsInteractive detection - ConsoleHost: $isConsoleHost, UserInteractive: $isUserInteractive, ScheduledTask: $isScheduledTask, Final: $($scriptContext.IsInteractive)" -Level DEBUG

    $invocationTrace = Get-InvocationTrace # Assumes Get-InvocationTrace is available from LoxoneUtils.Utility
    if ($invocationTrace -and $invocationTrace.ParentProcessCLI -like "*UpdateLoxone.ps1*") {
        $scriptContext.IsSelfInvokedForUpdateCheck = $true
    }
    Write-Log -Message "($FunctionName) IsSelfInvokedForUpdateCheck (based on ParentProcessCLI): $($scriptContext.IsSelfInvokedForUpdateCheck)" -Level DEBUG
    if ($scriptContext.Params.DebugMode) {
        Write-Log -Level DEBUG -Message "($FunctionName) --- Invocation Trace ---"
        if ($invocationTrace) {
            if ($invocationTrace.CallStack) { $invocationTrace.CallStack | ForEach-Object { Write-Log -Level DEBUG -Message "  CallStack: $_" } }
            Write-Log -Level DEBUG -Message "  ThisProcessCLI: $($invocationTrace.ThisProcessCLI)"
            Write-Log -Level DEBUG -Message "  ParentProcessCLI: $($invocationTrace.ParentProcessCLI)"
        } else { Write-Log -Level WARN -Message "($FunctionName) InvocationTrace is null."}
        Write-Log -Level DEBUG -Message "($FunctionName) --- End Invocation Trace ---"
    }

    # --- Task Registration (-RegisterTask switch) ---
    # If -RegisterTask is used, the script should register the task and exit. This is handled by the main script.
    # This function will just note if the condition is met.
    if ($scriptContext.Params.RegisterTask) {
        Write-Log -Message "($FunctionName) -RegisterTask specified. Main script will handle registration and exit." -Level INFO
        $scriptContext.Reason = "ActionRegisterTaskAndExit" # Signal to main script
        # No actual registration here; main script calls Register-ScheduledTaskForScript directly.
        return $scriptContext
    }

    # --- Automatic Interactive Task Registration (if needed and conditions met) ---
    # This logic is also complex and involves potential elevation.
    # The main script will call a dedicated function for this if needed, after this init.
    # For now, this function just gathers context. The decision to run task registration is in UpdateLoxone.ps1.


    # --- Define Paths and Constants ---
    $scriptContext.DownloadDir = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "Downloads"
    $scriptContext.MSListPath = Join-Path -Path $scriptContext.ScriptSaveFolder -ChildPath "UpdateLoxoneMSList.txt"
    $scriptContext.Constants = @{
        UpdateXmlUrl      = "https://update.loxone.com/updatecheck.xml"
        ZipFileName       = "LoxoneConfigSetup.zip" # Default, may change based on XML
        InstallerFileName = "loxoneconfigsetup.exe" # Default, may change based on XML
    }
    # These will be updated by Get-LoxoneUpdatePrerequisites if needed
    $scriptContext.Constants.ZipFilePath = Join-Path -Path $scriptContext.DownloadDir -ChildPath $scriptContext.Constants.ZipFileName
    $scriptContext.Constants.InstallerPath = Join-Path -Path $scriptContext.DownloadDir -ChildPath $scriptContext.Constants.InstallerFileName

    Write-Log -Message "($FunctionName) Download directory set to: '$($scriptContext.DownloadDir)'" -Level DEBUG

    # --- Initial Installed Versions (if not in SYSTEM initial re-launch phase) ---
    if (-not ($scriptContext.IsRunningAsSystem -and [string]::IsNullOrWhiteSpace($scriptContext.Params.PassedLogFile))) {
        $scriptContext.InstalledConfigExePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
        if ($scriptContext.InstalledConfigExePath) {
            Write-Log -Level INFO -Message "($FunctionName) [Config] Found installed Loxone Config path: $($scriptContext.InstalledConfigExePath)"
            $scriptContext.InitialInstalledConfigVersion = Get-InstalledVersion -ExePath $scriptContext.InstalledConfigExePath -ErrorAction SilentlyContinue
            if ($scriptContext.InitialInstalledConfigVersion) {
                Write-Log -Level INFO -Message "($FunctionName) [Config] Initial installed version: $($scriptContext.InitialInstalledConfigVersion)"
            } else {
                Write-Log -Level WARN -Message "($FunctionName) [Config] Failed to determine initial installed version from '$($scriptContext.InstalledConfigExePath)'."
            }
            # Loxone Icon Path
            $InstallDir = Split-Path -Parent $scriptContext.InstalledConfigExePath
            $PotentialIconPath = Join-Path -Path $InstallDir -ChildPath "LoxoneConfig.ico"
            if (Test-Path $PotentialIconPath) { $scriptContext.LoxoneIconPath = $PotentialIconPath }
        } else {
            Write-Log -Level INFO -Message "($FunctionName) [Config] Loxone Config installation not found."
        }

        try {
            $scriptContext.InitialLoxoneAppDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction SilentlyContinue # Changed to SilentlyContinue
            if ($scriptContext.InitialLoxoneAppDetails.Error) {
                Write-Log -Message "($FunctionName) [App] Failed to get Loxone App details from registry: $($scriptContext.InitialLoxoneAppDetails.Error)" -Level WARN
                $scriptContext.InitialLoxoneAppDetails = $null # Ensure it's null if error
            } elseif ($scriptContext.InitialLoxoneAppDetails) {
                Write-Log -Message ("($FunctionName) [App] Found Loxone App: Name='{0}', Path='{1}', FileVersion='{2}'" -f $scriptContext.InitialLoxoneAppDetails.ShortcutName, $scriptContext.InitialLoxoneAppDetails.InstallLocation, $scriptContext.InitialLoxoneAppDetails.FileVersion) -Level INFO
            } else {
                 Write-Log -Message "($FunctionName) [App] Loxone App details not found in registry (Get-AppVersionFromRegistry returned null/empty)." -Level INFO
            }
        } catch {
            Write-Log -Message "($FunctionName) [App] An error occurred during Get-AppVersionFromRegistry: $($_.Exception.Message)" -Level WARN
            $scriptContext.InitialLoxoneAppDetails = $null
        }
    }

    # --- TLS 1.2 ---
    try {
        # Support all TLS versions for compatibility with older Loxone devices
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls13
        Write-Log -Level INFO -Message "($FunctionName) Applied TLS 1.0/1.1/1.2/1.3 globally for Loxone compatibility."
    } catch {
        Write-Log -Level WARN -Message "($FunctionName) Failed to set all TLS versions: $($_.Exception.Message). Trying without TLS 1.3."
        try {
            # Fallback without TLS 1.3 (might not be available on older systems)
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls
            Write-Log -Level INFO -Message "($FunctionName) Applied TLS 1.0/1.1/1.2 globally (fallback)."
        } catch {
             Write-Log -Level WARN -Message "($FunctionName) Failed to set TLS versions (fallback): $($_.Exception.Message)"
        }
    }

    # --- Initialize Toast AppID (if not SYSTEM and interactive, or if an update might occur) ---
    # This should be done before any toast is shown by the main script.
    if (-not $scriptContext.IsRunningAsSystem) { # SYSTEM context won't show user toasts directly
        Initialize-LoxoneToastAppId # Sets $script:ResolvedToastAppId, accessible globally
        Write-Log -Level DEBUG -Message "($FunctionName) Called Initialize-LoxoneToastAppId. ResolvedToastAppId should be set to '$($script:ResolvedToastAppId)'."
    }

    Write-Log -Message "($FunctionName) Initialization workflow step finished." -Level INFO
    return $scriptContext
}

function Get-LoxoneUpdatePrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext # Contains URLs, Channels, initial versions etc.
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    Write-Log -Message "($FunctionName) Starting to get Loxone update prerequisites..." -Level INFO

    $result = [pscustomobject]@{
        Succeeded                       = $true
        Reason                          = ""
        Error                           = $null
        Component                       = "Prerequisites"
        ConfigUpdateNeeded              = $false
        LatestConfigVersion             = $null
        LatestConfigVersionNormalized   = $null
        ConfigZipUrl                    = $null
        ConfigExpectedZipSize           = $null
        ConfigExpectedCRC               = $null
        ConfigInstallerFileName         = $WorkflowContext.Constants.InstallerFileName # Default, may be overridden by Get-LoxoneUpdateData
        ConfigZipFileName               = $WorkflowContext.Constants.ZipFileName       # Default, may be overridden
        AppUpdateNeeded                 = $false
        LatestAppVersion                = $null # FileVersion style
        LatestAppVersionRaw             = $null # Original string from XML
        AppInstallerUrl                 = $null
        AppExpectedSize                 = $null
        AppExpectedCRC                  = $null
        AppInstallerFileName            = "LoxoneWindowsSetup.exe" # Default, may be overridden by Get-LoxoneUpdateData
        SelectedAppChannelName          = $null
    }

    try {
            # Determine actual boolean values for parameters, respecting defaults if not bound
        $checkAppUpdateActual = if ($WorkflowContext.Params.ContainsKey('UpdateLoxoneApp')) {
            [bool]$WorkflowContext.Params.UpdateLoxoneApp
        } else {
            # Parameter was not specified in PSBoundParameters, use its default from UpdateLoxone.ps1's param block
            $true # Default for -UpdateLoxoneApp in UpdateLoxone.ps1
        }

        $enableCRCActual = if ($WorkflowContext.Params.ContainsKey('EnableCRC')) {
            [bool]$WorkflowContext.Params.EnableCRC
        } else {
            $true # Default for -EnableCRC in UpdateLoxone.ps1
        }
        
        # For a switch, its presence in PSBoundParameters means it was specified.
        # If not present, its value is $false.
        # $WorkflowContext.Params.DebugMode directly gives the switch's boolean value if present, or $null if not.
        # So, a direct cast to bool or check for $null is better.
        $debugModeActual = [bool]($WorkflowContext.Params.DebugMode) # [bool]$null is $false

        $appChannelPreferenceActual = if ($WorkflowContext.Params.ContainsKey('UpdateLoxoneAppChannel')) {
            $WorkflowContext.Params.UpdateLoxoneAppChannel
        } else {
            "Latest" # Default value of UpdateLoxoneAppChannel parameter in UpdateLoxone.ps1
        }

$configChannelActual = if ($WorkflowContext.Params.ContainsKey('Channel')) {
            $WorkflowContext.Params.Channel
        } else {
            "Test" # Default value of Channel parameter in UpdateLoxone.ps1
        }
        $updateDataParams = @{
    UpdateXmlUrl         = $WorkflowContext.Constants.UpdateXmlUrl
            ConfigChannel        = $configChannelActual
            CheckAppUpdate       = $checkAppUpdateActual
            AppChannelPreference = $appChannelPreferenceActual
            EnableCRC            = $enableCRCActual
        }
        # Only add DebugMode to splatting hashtable if it's true, to avoid passing -DebugMode:$false
        if ($debugModeActual) {
            $updateDataParams.DebugMode = $true
        }

        Write-Log -Level DEBUG -Message "($FunctionName) Preparing to call Get-LoxoneUpdateData. Effective Params for splatting:"
        Write-Log -Level DEBUG -Message "($FunctionName) ConfigChannelActual: '$configChannelActual' (Type: $($configChannelActual.GetType().FullName))"
        Write-Log -Level DEBUG -Message "($FunctionName) CheckAppUpdateActual: '$checkAppUpdateActual' (Type: $($checkAppUpdateActual.GetType().FullName))"
        Write-Log -Level DEBUG -Message "($FunctionName) AppChannelPreferenceActual: '$appChannelPreferenceActual' (Type: $($appChannelPreferenceActual.GetType().FullName))"
        Write-Log -Level DEBUG -Message "($FunctionName) EnableCRCActual: '$enableCRCActual' (Type: $($enableCRCActual.GetType().FullName))"
        Write-Log -Level DEBUG -Message "($FunctionName) DebugModeActual (controls if -DebugMode is added to splat): '$debugModeActual' (Type: $($debugModeActual.GetType().FullName))"
        Write-Log -Level DEBUG -Message "($FunctionName) Final `$updateDataParams to be splatted: $($updateDataParams | Out-String)"

        $updateData = Get-LoxoneUpdateData @updateDataParams
        if ($updateData.Error) {
            throw "Error retrieving update data from Get-LoxoneUpdateData: $($updateData.Error)"
        }
        if ($null -eq $updateData.ConfigLatestVersion -and $null -eq $updateData.AppLatestVersion) {
            # If both are null, it's a more significant issue than just one component missing.
            throw "CRITICAL: Could not determine latest Loxone Config OR App version from update data. XML might be malformed or inaccessible."
        }
        if ($null -eq $updateData.ConfigLatestVersion) {
             Write-Log -Level WARN -Message "($FunctionName) Could not determine the latest Loxone Config version from the update data. Config update check will be skipped or fail."
        }


        $result.LatestConfigVersion           = $updateData.ConfigLatestVersion
        $result.LatestConfigVersionNormalized = Convert-VersionString $result.LatestConfigVersion # From LoxoneUtils.Utility
        $result.ConfigZipUrl                  = $updateData.ConfigZipUrl
        $result.ConfigExpectedZipSize         = $updateData.ConfigExpectedZipSize
        $result.ConfigExpectedCRC             = $updateData.ConfigExpectedCRC
        if ($updateData.ConfigInstallerFileName) { $result.ConfigInstallerFileName = $updateData.ConfigInstallerFileName } # Use from XML if provided
        if ($updateData.ConfigZipFileName) { $result.ConfigZipFileName = $updateData.ConfigZipFileName } # Use from XML if provided


        $result.LatestAppVersionRaw           = $updateData.AppLatestVersionRaw
        $result.LatestAppVersion              = $updateData.AppLatestVersion # Already FileVersion style
        $result.AppInstallerUrl               = $updateData.AppInstallerUrl
        $result.AppExpectedSize               = $updateData.AppExpectedSize
        $result.AppExpectedCRC                = $updateData.AppExpectedCRC
        $result.SelectedAppChannelName        = $updateData.SelectedAppChannelName
        if ($updateData.AppInstallerFileName) { 
            $result.AppInstallerFileName = $updateData.AppInstallerFileName 
        } elseif ($updateData.AppInstallerUrl) {
            # Derive filename from URL if not explicitly provided
            $urlFileName = [System.IO.Path]::GetFileName([System.Uri]::new($updateData.AppInstallerUrl).LocalPath)
            if (-not [string]::IsNullOrWhiteSpace($urlFileName)) {
                $result.AppInstallerFileName = $urlFileName
                Write-Log -Message "($FunctionName) Derived App installer filename from URL: '$urlFileName'" -Level DEBUG
            }
        }


        Write-Log -Message "($FunctionName) Successfully retrieved raw update data via Get-LoxoneUpdateData." -Level INFO
        if ($result.LatestConfigVersion) { Write-Log -Message "($FunctionName) [Config] Latest: $($result.LatestConfigVersion), URL: $($result.ConfigZipUrl), Zip: $($result.ConfigZipFileName), Installer: $($result.ConfigInstallerFileName)" -Level DEBUG }
        if ($result.LatestAppVersion) { Write-Log -Message "($FunctionName) [App] Latest ($($result.SelectedAppChannelName)): $($result.LatestAppVersion) (Raw: $($result.LatestAppVersionRaw)), URL: $($result.AppInstallerUrl), Installer: $($result.AppInstallerFileName)" -Level DEBUG }

        # --- Determine Config Update Needed ---
        if ($result.LatestConfigVersionNormalized) {
            $normalizedInstalledConfig = Convert-VersionString $WorkflowContext.InitialInstalledConfigVersion
            if ([string]::IsNullOrWhiteSpace($normalizedInstalledConfig)) {
                $result.ConfigUpdateNeeded = $true
                Write-Log -Message "($FunctionName) [Config] No initial Config version detected. Update required to '$($result.LatestConfigVersionNormalized)'." -Level INFO
            } elseif ($result.LatestConfigVersionNormalized -ne $normalizedInstalledConfig) {
                if ([Version]$result.LatestConfigVersionNormalized -gt [Version]$normalizedInstalledConfig) {
                    $result.ConfigUpdateNeeded = $true
                    Write-Log -Message "($FunctionName) [Config] Update required (Installed: '$($WorkflowContext.InitialInstalledConfigVersion)', Available: '$($result.LatestConfigVersionNormalized)')." -Level INFO
                } else {
                    Write-Log -Message "($FunctionName) [Config] Installed Config version '$($WorkflowContext.InitialInstalledConfigVersion)' is current or newer than available '$($result.LatestConfigVersionNormalized)'." -Level INFO
                }
            } else {
                Write-Log -Message "($FunctionName) [Config] Loxone Config is current (Version: $($WorkflowContext.InitialInstalledConfigVersion))." -Level INFO
            }
        } else {
            Write-Log -Message "($FunctionName) [Config] Latest Config version could not be determined. Cannot assess if update is needed." -Level WARN
        }


        # --- Determine App Update Needed ---
        # --- Determine App Update Needed ---
        # Use $checkAppUpdateActual which correctly reflects the parameter's default value if not explicitly passed
        Write-Log -Message "($FunctionName) [AppBlockEntryCheck] Before App UpdateNeeded block. checkAppUpdateActual: '$checkAppUpdateActual'. Result.LatestAppVersion has value: $([bool]$result.LatestAppVersion). Raw LatestAppVersion: '$($result.LatestAppVersion)'" -Level INFO
        if ($checkAppUpdateActual -and $result.LatestAppVersion) {
            $initialAppFileVersion = $WorkflowContext.InitialLoxoneAppDetails.FileVersion # Might be null if app not installed
            if ([string]::IsNullOrWhiteSpace($initialAppFileVersion)) {
                $result.AppUpdateNeeded = $true # App desired, latest known, current not installed
                Write-Log -Message "($FunctionName) [App] Update required. Latest '$($result.LatestAppVersion)' available, but Loxone App not currently installed or version unknown." -Level INFO
            } else {
                $normalizedLatestApp = Convert-VersionString $result.LatestAppVersion
                $normalizedInstalledApp = Convert-VersionString $initialAppFileVersion
                
                # Consolidated version comparison (was 5 verbose debug lines)
                Write-Log -Message "($FunctionName) [App] Version check: Installed='$normalizedInstalledApp' vs Latest='$normalizedLatestApp'" -Level INFO

                try {
                    $vNormalizedLatestApp = [Version]$normalizedLatestApp
                    $vNormalizedInstalledApp = [Version]$normalizedInstalledApp

                    $areNotEqual = $vNormalizedLatestApp -ne $vNormalizedInstalledApp

                    if ($areNotEqual) { # Equivalent to original line 439
                        $isLatestGreaterThanInstalled = $vNormalizedLatestApp -gt $vNormalizedInstalledApp
                        if ($isLatestGreaterThanInstalled) { # Equivalent to original line 440
                            $result.AppUpdateNeeded = $true
                            Write-Log -Message "($FunctionName) [App] Update needed (Latest '$normalizedLatestApp' > Installed '$normalizedInstalledApp'). Set AppUpdateNeeded=True" -Level INFO
                        } else {
                            Write-Log -Message "($FunctionName) [App] No update needed (Latest '$normalizedLatestApp' <= Installed '$normalizedInstalledApp')" -Level INFO
                        }
                    } else {
                        Write-Log -Message "($FunctionName) [App] Loxone App is current (version '$normalizedLatestApp')" -Level INFO
                    }
                } catch {
                    Write-Log -Message "($FunctionName) [AppDebug] ERROR during version comparison or casting: $($_.Exception.Message)" -Level ERROR
                }
            }
        } elseif ($checkAppUpdateActual -and -not $result.LatestAppVersion) { # Also use $checkAppUpdateActual here
            Write-Log -Message "($FunctionName) [App] Update for Loxone App was requested, but latest version details could not be retrieved. Skipping App update check." -Level WARN
        }

    } catch {
        $result.Succeeded = $false
        $result.Reason = "GetPrerequisitesFailed"
        $result.Error = $_
        Write-Log -Message "($FunctionName) Error getting prerequisites: $($_.Exception.Message). Full Error: ($($_ | Out-String))" -Level ERROR
    }
    Write-Log -Message "($FunctionName) Prerequisite check finished. ConfigUpdateNeeded: $($result.ConfigUpdateNeeded), AppUpdateNeeded: $($result.AppUpdateNeeded)." -Level INFO
    return $result
}

function Invoke-DownloadLoxoneConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext, # Contains ScriptSaveFolder, DownloadDir, Params (for IsInteractive, DebugMode), etc.
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ConfigTargetInfo, # Contains DownloadUrl, ZipFilePath, ExpectedSize, ExpectedCRC
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState, # To update CurrentWeight, CurrentStep, TotalSteps, etc.
        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressReporter = $null
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    $result = [pscustomobject]@{
        Succeeded       = $false
        Reason          = ""
        Error           = $null
        Component       = "Config"
        Action          = "Download"
        FilePath        = $ConfigTargetInfo.ZipFilePath
        DownloadSkipped = $false
    }

    Write-Log -Message "($FunctionName) Starting Loxone Config download step." -Level INFO
    try {
        $zipFilePath = $ConfigTargetInfo.ZipFilePath
        $expectedCRC = $ConfigTargetInfo.ExpectedCRC
        $expectedSize = $ConfigTargetInfo.ExpectedSize

        # Check for existing valid ZIP file first.
        if (Test-Path $zipFilePath -PathType Leaf) {
            Write-Log -Message "($FunctionName) Existing ZIP file found at '$zipFilePath'. Verifying..." -Level DEBUG
            $enableCRCCheckValue = if ($WorkflowContext.Params.ContainsKey('EnableCRC')) {
                [bool]$WorkflowContext.Params.EnableCRC
            } else {
                $true # Default from UpdateLoxone.ps1's EnableCRC parameter
            }
            Write-Log -Message "($FunctionName) Effective EnableCRC for Test-ExistingFile: $enableCRCCheckValue" -Level DEBUG

            $fileCheckParams = @{
                FilePath      = $zipFilePath
                ExpectedCRC   = $expectedCRC
                ExpectedSize  = $expectedSize
                EnableCRC     = $enableCRCCheckValue
                ErrorAction   = 'SilentlyContinue'
            }
            $existingZipValid = Test-ExistingFile @fileCheckParams # Assumes Test-ExistingFile is in LoxoneUtils.Utility

            if ($existingZipValid) {
                Write-Log -Message "($FunctionName) Existing Loxone Config ZIP file '$zipFilePath' is valid. Skipping download." -Level INFO
                $result.Succeeded = $true
                $result.DownloadSkipped = $true
                $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'DownloadConfig'
                return $result
            } else {
                Write-Log -Message "($FunctionName) Existing Loxone Config ZIP file '$zipFilePath' is invalid or check failed. Proceeding with download." -Level WARN
                Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue # Remove invalid/old zip
            }
        }

        if (-not (Test-Path -Path $WorkflowContext.DownloadDir -PathType Container)) {
            Write-Log -Message "($FunctionName) Download directory '$($WorkflowContext.DownloadDir)' not found. Creating..." -Level INFO
            New-Item -Path $WorkflowContext.DownloadDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # If we reach here, a download is needed.
        $ScriptGlobalState.Value.currentStep++ # Assuming step count is managed by caller or a pre-step
        $ScriptGlobalState.Value.currentDownload++ # Assuming download count is managed by caller or a pre-step
        
        # Calculate progress percentage
        $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
            [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
        } else { 0 }
        
        # Use progress reporter if available, otherwise fall back to toast
        if ($ProgressReporter) {
            $currentOp = "$($ConfigTargetInfo.ZipFileName) ($($ScriptGlobalState.Value.currentDownload)/$($ScriptGlobalState.Value.totalDownloads))"
            & $ProgressReporter -Operation "Downloading Loxone Config" `
                               -Status "Starting download" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation $currentOp
        } else {
            # Fallback to direct toast update for backward compatibility
            $toastParams = @{
                StepNumber       = $ScriptGlobalState.Value.currentStep
                TotalSteps       = $ScriptGlobalState.Value.totalSteps
                StepName         = "Downloading Loxone Config"
                DownloadFileName = $ConfigTargetInfo.ZipFileName
                DownloadNumber   = $ScriptGlobalState.Value.currentDownload
                TotalDownloads   = $ScriptGlobalState.Value.totalDownloads
                CurrentWeight    = $ScriptGlobalState.Value.CurrentWeight
                TotalWeight      = $ScriptGlobalState.Value.TotalWeight
            }
            try {
                Update-PersistentToast @toastParams -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-DownloadLoxoneConfig) called successfully."
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-DownloadLoxoneConfig: $($_.Exception.ToString())"
            }
        }
        $downloadParams = @{
            Url              = $ConfigTargetInfo.DownloadUrl
            DestinationPath  = $ConfigTargetInfo.ZipFilePath # ZipFilePath from ConfigTargetInfo
            ActivityName     = "Downloading Loxone Config Update"
            ExpectedCRC32    = $ConfigTargetInfo.ExpectedCRC
            ExpectedFilesize = $ConfigTargetInfo.ExpectedSize
            MaxRetries       = 1 # As per original script
            IsInteractive    = $WorkflowContext.IsInteractive
            # Pass toast parameters for Invoke-LoxoneDownload to handle progress within the download
            StepNumber       = $ScriptGlobalState.Value.currentStep
            TotalSteps       = $ScriptGlobalState.Value.totalSteps
            StepName         = "Downloading Loxone Config" # Redundant with ActivityName but for consistency
            DownloadNumber   = $ScriptGlobalState.Value.currentDownload
            TotalDownloads   = $ScriptGlobalState.Value.totalDownloads
            CurrentWeight    = $ScriptGlobalState.Value.CurrentWeight
            TotalWeight      = $ScriptGlobalState.Value.TotalWeight
            ErrorAction      = 'Stop' # Critical for function's try/catch
        }
        
        # Add ProgressReporter if available
        if ($ProgressReporter) {
            $downloadParams.ProgressReporter = $ProgressReporter
        }

        Write-Log -Message "($FunctionName) Calling Invoke-LoxoneDownload for Config ZIP..." -Level DEBUG
        $downloadSuccess = Invoke-LoxoneDownload @downloadParams
        if (-not $downloadSuccess) {
            # Invoke-LoxoneDownload already logs details. This function's catch will handle it if an exception was thrown.
            # If it returns $false without throwing, we set the reason.
            $result.Reason = "DownloadCmdletFailed"
            Write-Log -Message "($FunctionName) Invoke-LoxoneDownload returned `$false." -Level WARN
            # Error will be caught by this function's catch if Invoke-LoxoneDownload threw terminating error
        } else {
            $result.Succeeded = $true
            Write-Log -Message "($FunctionName) Loxone Config ZIP download reported as successful." -Level INFO
            $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'DownloadConfig' # Assumes Get-StepWeight is accessible
            
            # Report download completion
            if ($ProgressReporter) {
                $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
                    [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
                } else { 0 }
                
                & $ProgressReporter -Operation "Downloading Loxone Config" `
                                   -Status "Download completed" `
                                   -PercentComplete $progressPercent `
                                   -CurrentOperation "Downloaded $($ConfigTargetInfo.ZipFileName)"
            }
        }

    } catch {
        $result.Succeeded = $false
        $result.Reason = "DownloadException"
        $result.Error = $_
        Write-Log -Message "($FunctionName) Exception during Loxone Config download: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    }
    return $result
}

function Invoke-ExtractLoxoneConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ConfigTargetInfo, # Contains ZipFilePath, InstallerPath, ExpectedInstallerName
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState,
        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressReporter = $null
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    $result = [pscustomobject]@{
        Succeeded           = $false
        Reason              = ""
        Error               = $null
        Component           = "Config"
        Action              = "Extract"
        InstallerPath       = $ConfigTargetInfo.InstallerPath
        SignatureVerified   = $false # Will be set if signature check is done here
    }
    Write-Log -Message "($FunctionName) Starting Loxone Config extraction step." -Level INFO

    try {
        $zipFilePath = $ConfigTargetInfo.ZipFilePath
        $destinationPath = $WorkflowContext.DownloadDir
        $expectedInstallerPath = $ConfigTargetInfo.InstallerPath # Path including the filename

        if (-not (Test-Path $zipFilePath -PathType Leaf)) {
            throw "ZIP file not found at '$zipFilePath'. Cannot extract."
        }

        # Progress update
        $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
            [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
        } else { 0 }
        
        # Use progress reporter if available, otherwise fall back to toast
        if ($ProgressReporter) {
            & $ProgressReporter -Operation "Extracting Config Installer" `
                               -Status "Extracting from ZIP file" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation "Extracting $($ConfigTargetInfo.ExpectedInstallerName)"
        } else {
            # Fallback to direct toast update for backward compatibility
            $toastParams = @{
                StepNumber    = $ScriptGlobalState.Value.currentStep
                TotalSteps    = $ScriptGlobalState.Value.totalSteps
                StepName      = "Extracting Config Installer"
                CurrentWeight = $ScriptGlobalState.Value.CurrentWeight
                TotalWeight   = $ScriptGlobalState.Value.TotalWeight
            }
            try {
                Update-PersistentToast @toastParams -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-ExtractLoxoneConfig) called successfully."
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-ExtractLoxoneConfig: $($_.Exception.ToString())"
            }
        }
        if (Test-Path $expectedInstallerPath) {
            Write-Log -Level DEBUG -Message "($FunctionName) Removing existing installer before extraction: $expectedInstallerPath"
            Remove-Item -Path $expectedInstallerPath -Force -ErrorAction SilentlyContinue
        }

        # Expand-Archive does not have built-in retry or detailed progress for this function's design
        # LoxoneUtils.Installation might have Expand-LoxoneConfigArchive which could be used if it offers more.
        # Using direct Expand-Archive as per original script's direct usage.
        $originalProgressPreference = $ProgressPreference
        try {
            $ProgressPreference = 'SilentlyContinue' # Suppress console progress bar
            
            # Send a toast update right before extraction to keep it alive
            if ($Global:PersistentToastInitialized) {
                try {
                    Update-PersistentToast -StepNumber $ScriptGlobalState.Value.currentStep `
                        -TotalSteps $ScriptGlobalState.Value.totalSteps `
                        -StepName "Extracting Config Installer..." `
                        -CurrentWeight $ScriptGlobalState.Value.CurrentWeight `
                        -TotalWeight $ScriptGlobalState.Value.TotalWeight `
                        -IsInteractive ([bool]$WorkflowContext.IsInteractive) `
                        -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) `
                        -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) `
                        -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) `
                        -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                    Write-Log -Level DEBUG -Message "($FunctionName) Sent keep-alive toast update before extraction"
                } catch {
                    Write-Log -Level DEBUG -Message "($FunctionName) Failed to send keep-alive toast update: $_"
                }
            }
            
            Expand-Archive -Path $zipFilePath -DestinationPath $destinationPath -Force -ErrorAction Stop
        } finally {
            $ProgressPreference = $originalProgressPreference
        }

        if (-not (Test-Path $expectedInstallerPath -PathType Leaf)) {
            throw "Installer file '$expectedInstallerPath' not found after extraction from '$zipFilePath'."
        }
        Write-Log -Message "($FunctionName) Installer extracted to $expectedInstallerPath." -Level INFO
        $result.Succeeded = $true
        $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'ExtractConfig'
        
        # Report extraction completion
        if ($ProgressReporter) {
            $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
                [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
            } else { 0 }
            
            & $ProgressReporter -Operation "Extracting Config Installer" `
                               -Status "Extraction completed" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation "Extracted $($ConfigTargetInfo.ExpectedInstallerName)"
        }

        # Installer Signature Verification (as per original script logic post-extraction)
        # This could be a separate step in the pipeline, but original did it right after extraction.
        # For now, including it here.
        Write-Log -Message "($FunctionName) Verifying Config Installer Signature for '$expectedInstallerPath'..." -Level INFO
        
        # Use progress reporter if available
        if ($ProgressReporter) {
            $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
                [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
            } else { 0 }
            
            & $ProgressReporter -Operation "Verifying Config Installer" `
                               -Status "Checking digital signature" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation "Verifying $($ConfigTargetInfo.ExpectedInstallerName)"
        } else {
            # Fallback to direct toast update for backward compatibility
            $toastParamsSig = @{
                StepNumber    = $ScriptGlobalState.Value.currentStep
                TotalSteps    = $ScriptGlobalState.Value.totalSteps
                StepName      = "Verifying Config Installer Signature"
                CurrentWeight = $ScriptGlobalState.Value.CurrentWeight
                TotalWeight   = $ScriptGlobalState.Value.TotalWeight
            }
            try {
                Update-PersistentToast @toastParamsSig -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-ExtractLoxoneConfig - Signature) called successfully."
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-ExtractLoxoneConfig (Signature): $($_.Exception.ToString())"
            }
        }
        # $ConfigTargetInfo should ideally have an ExpectedXmlSignature property if it's available from prerequisites
        # if ($ConfigTargetInfo.ExpectedXmlSignature) { ... }
        # For now, assuming signature check is always attempted if Get-ExecutableSignature is available.
        # The original script's $ExpectedXmlSignature check was flawed. A proper check involves comparing to a known good signature.
        # Here, we just check if the signature is 'Valid'.

        $sigCheckResult = Get-ExecutableSignature -ExePath $expectedInstallerPath -ErrorAction Stop # From LoxoneUtils.Utility
        if (-not $sigCheckResult) {
            throw "Get-ExecutableSignature returned null for '$expectedInstallerPath'."
        }
        if ($sigCheckResult.Status -ne 'Valid') {
            throw "Installer '$expectedInstallerPath' signature validation failed. Status: $($sigCheckResult.Status). Signer: $($sigCheckResult.SignerName)"
        }
        $result.SignatureVerified = $true
        Write-Log -Message "($FunctionName) Installer signature verified successfully. Status: $($sigCheckResult.Status), Signer: $($sigCheckResult.SignerName)" -Level INFO
        
        # Report signature verification completion
        if ($ProgressReporter) {
            $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
                [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
            } else { 0 }
            
            & $ProgressReporter -Operation "Verifying Config Installer" `
                               -Status "Signature verified successfully" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation "Verified: $($sigCheckResult.SignerName)"
        }

    } catch {
        $result.Succeeded = $false
        $result.Reason = if ($result.SignatureVerified -eq $false -and $_.Exception.Message -like "*signature validation failed*") {"ExtractionSucceededSignatureFailed"} elseif ($_.Exception.Message -like "*not found after extraction*") {"ExtractionFailedNotFound"} else {"ExtractionException"}
        $result.Error = $_
        Write-Log -Message "($FunctionName) Exception during Loxone Config extraction/signature check: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    }
    return $result
}

function Invoke-InstallLoxoneConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ConfigTargetInfo, # Contains InstallerPath, TargetVersion (Normalized)
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState,
        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressReporter = $null
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    # Determine if this is an update or install based on InitialVersion
    $isUpdate = -not [string]::IsNullOrWhiteSpace($WorkflowContext.InitialInstalledConfigVersion)
    
    $result = [pscustomobject]@{
        Succeeded          = $false
        Reason             = ""
        Error              = $null
        Component          = "Config"
        Action             = if ($isUpdate) { "Update" } else { "Install" }
        InitialVersion     = $WorkflowContext.InitialInstalledConfigVersion
        TargetVersion      = $ConfigTargetInfo.TargetVersion
        VersionAfterUpdate = $null
        UpdatePerformed    = $true
        InstallSkipped     = $false
    }
    Write-Log -Message "($FunctionName) Starting Loxone Config $($result.Action.ToLower()) step." -Level INFO

    try { # MAIN FUNCTION TRY BLOCK
        $installerPath = $ConfigTargetInfo.InstallerPath
        $installerLogFileName = "LoxoneConfig_Install_$(Get-Date -Format 'yyyyMMddHHmmss').log"
        $installerLogPath = Join-Path -Path $WorkflowContext.LogDir -ChildPath $installerLogFileName
        $quotedInstallerLogPath = "`"$installerLogPath`""

        $effectiveInstallMode = "SILENT" # Default value from UpdateLoxone.ps1
        if ($WorkflowContext.Params.ContainsKey('InstallMode') -and -not ([string]::IsNullOrWhiteSpace($WorkflowContext.Params.InstallMode))) {
            $effectiveInstallMode = $WorkflowContext.Params.InstallMode
        }
        Write-Log -Message "($FunctionName) Effective InstallMode for installer: $effectiveInstallMode" -Level DEBUG

        $installArgsArray = @(
            "/$effectiveInstallMode",
            "/LOG=$quotedInstallerLogPath" # Format /LOG="C:\Path\To\Log.log" (Removed colon)
        )
        Write-Log -Message "($FunctionName) Installer will log to: $installerLogPath" -Level INFO
        Write-Log -Message "($FunctionName) Installer arguments: $($installArgsArray -join ' ')" -Level DEBUG

        $anyProcessRunning = $false
        $processesToCheck = @("LoxoneConfig", "loxonemonitor", "LoxoneLiveView")
        foreach ($procName in $processesToCheck) {
            if (Get-ProcessStatus -ProcessName $procName -StopProcess:$false -ErrorAction SilentlyContinue) {
                $anyProcessRunning = $true
                Write-Log -Message "($FunctionName) Detected running Loxone process before install: $procName" -Level INFO
            }
        }

        if ($anyProcessRunning -and $WorkflowContext.Params.SkipUpdateIfAnyProcessIsRunning) {
            Write-Log -Message "($FunctionName) Skipping Config installation because one or more Loxone processes are running and -SkipUpdateIfAnyProcessIsRunning was specified." -Level WARN
            $result.Succeeded = $true
            $result.Reason = "InstallSkippedProcessRunning"
            $result.InstallSkipped = $true
            $result.UpdatePerformed = $false
            
            $toastParamsSkip = @{
                StepNumber    = $ScriptGlobalState.Value.currentStep
                TotalSteps    = $ScriptGlobalState.Value.totalSteps
                StepName      = "Skipped Install: Loxone process running"
                CurrentWeight = $ScriptGlobalState.Value.CurrentWeight
                TotalWeight   = $ScriptGlobalState.Value.TotalWeight
            }
            try {
                Update-PersistentToast @toastParamsSkip -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Skip): $($_.Exception.ToString())"
            }
            return $result
        }

        if ($anyProcessRunning -and $WorkflowContext.Params.CloseApplications) {
            Write-Log -Message "($FunctionName) Closing Loxone applications as -CloseApplications was specified..." -Level INFO
            $toastParamsClose = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="Closing Loxone Apps"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
            try {
                Update-PersistentToast @toastParamsClose -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Close Apps): $($_.Exception.ToString())"
            }
            foreach ($procName in $processesToCheck) {
                Get-ProcessStatus -ProcessName $procName -StopProcess:$true -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 3
        } elseif ($anyProcessRunning) {
            Write-Log -Message "($FunctionName) Loxone processes are running, but -CloseApplications not specified. Installation might fail or require user intervention." -Level WARN
            $toastParamsWarn = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="WARN: Loxone Processes Running"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
            try {
                Update-PersistentToast @toastParamsWarn -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Warn Processes): $($_.Exception.ToString())"
            }
        }

        $toastParamsInstall = @{
            StepNumber        = $ScriptGlobalState.Value.currentStep
            TotalSteps        = $ScriptGlobalState.Value.totalSteps
            StepName          = "$($result.Action)ing Loxone Config"
            CurrentWeight     = $ScriptGlobalState.Value.CurrentWeight
            TotalWeight       = $ScriptGlobalState.Value.TotalWeight
            ProgressPercentage = 0           # Reset progress bar for installation phase
            DownloadFileName  = ""           # Clear download-specific fields
            DownloadNumber    = 0
            TotalDownloads    = 0
        }
        try {
            Update-PersistentToast @toastParamsInstall -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        } catch {
            Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Install): $($_.Exception.ToString())"
        }
        
        # Installer Execution Block
        Write-Log -Message "($FunctionName) Executing Loxone Config installer: '$installerPath' with arguments '$($installArgsArray -join ' ')'" -Level DEBUG
        $exitCode = -99 # Initialize with a distinct pre-run value

        try { # INSTALLER EXECUTION TRY (starts line 982 in original numbering)
            Write-Log -Message "($FunctionName) DIAGNOSTIC: Running Start-Process without -WindowStyle Hidden." -Level DEBUG
            if (-not (Test-Path -Path $installerPath -PathType Leaf)) {
                Write-Log -Message "($FunctionName) CRITICAL: Installer executable not found at '$installerPath' right before Start-Process call." -Level ERROR
                throw "Installer executable not found: $installerPath"
            }
            Write-Log -Message "($FunctionName) Installer executable confirmed to exist at '$installerPath'." -Level DEBUG
            $installerDir = Split-Path -Path $installerPath -Parent
            Write-Log -Message "($FunctionName) About to call Start-Process. Installer: '$installerPath'. Args: '$($installArgsArray -join ' ')'. WorkingDirectory: '$installerDir'" -Level DEBUG
            
            $process = $null
            
            try { # START-PROCESS TRY (starts line 1000 in original numbering)
                Write-Log -Message "($FunctionName) Entering Start-Process try block." -Level DEBUG
                $process = Start-Process -FilePath $installerPath -ArgumentList $installArgsArray -WorkingDirectory $installerDir -Wait -PassThru -ErrorAction Stop
                Write-Log -Message "($FunctionName) Start-Process call completed." -Level DEBUG

                if ($null -ne $process) {
                    Write-Log -Message "($FunctionName) Process object IS NOT NULL. Attempting to get ExitCode." -Level DEBUG
                    $exitCode = $process.ExitCode
                    Write-Log -Message "($FunctionName) Process.ExitCode is: '$($process.ExitCode)'" -Level DEBUG
                } else {
                    Write-Log -Message "($FunctionName) Process object IS NULL after Start-Process." -Level WARN
                    $exitCode = -2
                }
            } catch { # START-PROCESS CATCH (starts line 1013 in original numbering)
                $CaughtError = $_
                Write-Log -Message "($FunctionName) CAUGHT error executing Start-Process: $($CaughtError.Exception.Message)" -Level ERROR
                Write-Log -Message "($FunctionName) Full error object from Start-Process catch: $($CaughtError | Out-String)" -Level DEBUG
                $exitCode = -1
            } # END START-PROCESS CATCH (ends line 1018 in original numbering)
            
            Write-Log -Message "($FunctionName) After Start-Process try-catch. Current ExitCode value: '$exitCode'" -Level DEBUG
            if ($null -eq $exitCode) {
                Write-Log -Message "($FunctionName) ExitCode is NULL after Start-Process block, defaulting to -3." -Level WARN
                $exitCode = -3
            }
            Write-Log -Message "($FunctionName) Loxone Config installer process exited with code: $exitCode" -Level INFO

            if ($exitCode -ne 0) {
                Write-Log -Message "($FunctionName) Installer returned non-zero exit code: $exitCode. Installation may have failed." -Level WARN
            }
        } catch { # INSTALLER EXECUTION CATCH (starts line 1034 in original numbering)
            $CaughtInstallerBlockError = $_
            Write-Log -Message "($FunctionName) Error within the installer execution block (e.g., Test-Path failed or other logic): $($CaughtInstallerBlockError.Exception.Message)" -Level ERROR
            Write-Log -Message "($FunctionName) Full error object from installer execution block catch: $($CaughtInstallerBlockError | Out-String)" -Level DEBUG
            if ($exitCode -eq -99) {
                $exitCode = -5
            }
        } # END INSTALLER EXECUTION CATCH (ends line 1042 in original numbering)
        
        # Verification (starts line 1043 in original numbering, after the removed brace)
        Write-Log -Message "($FunctionName) Verifying Loxone Config installation..." -Level INFO
        $toastParamsVerify = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="Verifying Loxone Config Installation"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
        try {
            Update-PersistentToast @toastParamsVerify -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        } catch {
            Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Verify): $($_.Exception.ToString())"
        }
        Start-Sleep -Seconds 2
        $newlyInstalledExePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
        $newlyInstalledVersion = ""
        if ($newlyInstalledExePath -and (Test-Path $newlyInstalledExePath)) {
            $newlyInstalledVersion = Get-InstalledVersion -ExePath $newlyInstalledExePath -ErrorAction SilentlyContinue
        }
        $result.VersionAfterUpdate = $newlyInstalledVersion
        
        $normalizedNewInstalled = Convert-VersionString $newlyInstalledVersion
        $normalizedTarget = Convert-VersionString $ConfigTargetInfo.TargetVersion

        if ($normalizedNewInstalled -eq $normalizedTarget) {
            $result.Succeeded = $true
            Write-Log -Message "($FunctionName) Successfully $($result.Action.ToLower())ed and verified Loxone Config to version $newlyInstalledVersion." -Level INFO
            $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'VerifyConfig'
            $toastParamsSuccess = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="Conf v$newlyInstalledVersion"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
            try {
                Update-PersistentToast @toastParamsSuccess -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed $true -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call (Success): $($_.Exception.ToString())"
            }
        } else {
            $result.Reason = "VerificationFailed"
            $errorMsg = "Loxone Config update verification failed! Expected '$normalizedTarget', but found '$normalizedNewInstalled' (or version check failed)."
            if ($exitCode -ne 0) {
                $errorMsg += " Installer also exited with code $exitCode."
                $result.Reason = "InstallFailedAndVerificationFailed"
            }
            Write-Log -Message "($FunctionName) $errorMsg" -Level ERROR
            throw $errorMsg
        }
    } # END MAIN FUNCTION TRY BLOCK (ends line 1117 in original numbering)
    catch { # MAIN FUNCTION CATCH BLOCK (starts line 1118 in original numbering)
        $result.Succeeded = $false
        if ([string]::IsNullOrWhiteSpace($result.Reason)) {
            $result.Reason = "InstallException"
        }
        $result.Error = $_
        Write-Log -Message "($FunctionName) Exception during Loxone Config installation/verification: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    } # END MAIN FUNCTION CATCH BLOCK (ends line 1127 in original numbering)
    return $result
} # END FUNCTION (ends line 1129 in original numbering)
function Invoke-DownloadLoxoneApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AppTargetInfo, # Contains DownloadUrl, InstallerFileName, ExpectedSize, ExpectedCRC
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState,
        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressReporter = $null
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    $result = [pscustomobject]@{
        Succeeded       = $false
        Reason          = ""
        Error           = $null
        Component       = "App"
        Action          = "Download"
        FilePath        = "" # Will be set to the full installer path
        DownloadSkipped = $false
    }

    Write-Log -Message "($FunctionName) Starting Loxone App download step." -Level INFO
    try {
        $appInstallerFileName = $AppTargetInfo.InstallerFileName
        $appInstallerPath = Join-Path -Path $WorkflowContext.DownloadDir -ChildPath $appInstallerFileName
        $result.FilePath = $appInstallerPath

        # Check for existing valid installer first. If valid, skip download and toast.
        $appInstallerCheckResult = Test-ExistingInstaller -InstallerPath $appInstallerPath -TargetVersion $AppTargetInfo.TargetVersion -ComponentName "App" -ErrorAction SilentlyContinue
        if ($appInstallerCheckResult.IsValid) {
            Write-Log -Message "($FunctionName) Valid existing Loxone App installer found at '$appInstallerPath'. Skipping download." -Level INFO
            $result.Succeeded = $true
            $result.DownloadSkipped = $true
            # Ensure CurrentWeight is updated as if download happened for progress consistency
            $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'DownloadApp'
            return $result
        } elseif ($appInstallerCheckResult.Reason -ne "Not found") {
             Write-Log -Message "($FunctionName) Existing App installer '$appInstallerPath' is invalid or version mismatch ($($appInstallerCheckResult.Reason)). Removing if present and proceeding with download." -Level WARN
             if(Test-Path $appInstallerPath) {Remove-Item -Path $appInstallerPath -Force -ErrorAction SilentlyContinue}
        }

        # If we reach here, a download is needed.
        if (-not (Test-Path -Path $WorkflowContext.DownloadDir -PathType Container)) {
            Write-Log -Message "($FunctionName) Download directory '$($WorkflowContext.DownloadDir)' not found. Creating..." -Level INFO
            New-Item -Path $WorkflowContext.DownloadDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $ScriptGlobalState.Value.currentStep++
        $ScriptGlobalState.Value.currentDownload++
        
        # Calculate progress percentage
        $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
            [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
        } else { 0 }
        
        # Use progress reporter if available, otherwise fall back to toast
        if ($ProgressReporter) {
            $currentOp = "$appInstallerFileName ($($ScriptGlobalState.Value.currentDownload)/$($ScriptGlobalState.Value.totalDownloads))"
            & $ProgressReporter -Operation "Downloading Loxone App" `
                               -Status "Starting download" `
                               -PercentComplete $progressPercent `
                               -CurrentOperation $currentOp
        } else {
            # Fallback to direct toast update for backward compatibility
            $toastParams = @{
                StepNumber       = $ScriptGlobalState.Value.currentStep
                TotalSteps       = $ScriptGlobalState.Value.totalSteps
                StepName         = "Downloading Loxone App"
                DownloadFileName = $appInstallerFileName
                DownloadNumber   = $ScriptGlobalState.Value.currentDownload
                TotalDownloads   = $ScriptGlobalState.Value.totalDownloads
                CurrentWeight    = $ScriptGlobalState.Value.CurrentWeight
                TotalWeight      = $ScriptGlobalState.Value.TotalWeight
            }
            try {
                Update-PersistentToast @toastParams -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-DownloadLoxoneApp) called successfully."
            } catch {
                Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-DownloadLoxoneApp: $($_.Exception.ToString())"
            }
        }
        $downloadParams = @{
            Url              = $AppTargetInfo.DownloadUrl
            DestinationPath  = $appInstallerPath
            ActivityName     = "Downloading Loxone App Update"
            ExpectedCRC32    = $AppTargetInfo.ExpectedCRC
            ExpectedFilesize = $AppTargetInfo.ExpectedSize
            MaxRetries       = 1
            IsInteractive    = $WorkflowContext.IsInteractive
            StepNumber       = $ScriptGlobalState.Value.currentStep
            TotalSteps       = $ScriptGlobalState.Value.totalSteps
            StepName         = "Downloading Loxone App"
            # DownloadFileName is not a direct parameter of Invoke-LoxoneDownload;
            # Invoke-LoxoneDownload uses DestinationPath to derive filename for its internal toast updates if needed.
            # ActivityName is used for overall activity logging.
            DownloadNumber   = $ScriptGlobalState.Value.currentDownload
            TotalDownloads   = $ScriptGlobalState.Value.totalDownloads
            CurrentWeight    = $ScriptGlobalState.Value.CurrentWeight
            TotalWeight      = $ScriptGlobalState.Value.TotalWeight
            ErrorAction      = 'Stop'
        }
        
        # Add ProgressReporter if available
        if ($ProgressReporter) {
            $downloadParams.ProgressReporter = $ProgressReporter
        }

        Write-Log -Message "($FunctionName) Calling Invoke-LoxoneDownload for App installer..." -Level DEBUG
        $downloadSuccess = Invoke-LoxoneDownload @downloadParams

        if (-not $downloadSuccess) {
            $result.Reason = "DownloadCmdletFailed"
            Write-Log -Message "($FunctionName) Invoke-LoxoneDownload returned `$false for App." -Level WARN
        } else {
            $result.Succeeded = $true
            Write-Log -Message "($FunctionName) Loxone App download reported as successful." -Level INFO
            $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'DownloadApp'
            
            # Report download completion
            if ($ProgressReporter) {
                $progressPercent = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { 
                    [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) 
                } else { 0 }
                
                & $ProgressReporter -Operation "Downloading Loxone App" `
                                   -Status "Download completed" `
                                   -PercentComplete $progressPercent `
                                   -CurrentOperation "Downloaded $appInstallerFileName"
            }
        }

    } catch {
        $result.Succeeded = $false
        $result.Reason = "DownloadException"
        $result.Error = $_
        Write-Log -Message "($FunctionName) Exception during Loxone App download: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    }
    return $result
}

function Invoke-InstallLoxoneApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AppTargetInfo, # Contains InstallerFileName, TargetVersion, InitialVersion (from InitialLoxoneAppDetails)
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState,
        [Parameter(Mandatory=$false)]
        [scriptblock]$ProgressReporter = $null
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    # Determine if this is an update or install based on InitialVersion
    $isUpdate = -not [string]::IsNullOrWhiteSpace($AppTargetInfo.InitialVersion)
    
    $result = [pscustomobject]@{
        Succeeded          = $false
        Reason             = ""
        Error              = $null
        Component          = "App"
        Action             = if ($isUpdate) { "Update" } else { "Install" }
        InitialVersion     = $AppTargetInfo.InitialVersion # FileVersion from registry
        TargetVersion      = $AppTargetInfo.TargetVersion  # FileVersion from XML
        VersionAfterUpdate = $null
        UpdatePerformed    = $true
        InstallSkipped     = $false
    }
    Write-Log -Message "($FunctionName) Starting Loxone App $($result.Action.ToLower()) step." -Level INFO

    try {
        $appInstallerFileName = $AppTargetInfo.InstallerFileName
        $appInstallerPath = Join-Path -Path $WorkflowContext.DownloadDir -ChildPath $appInstallerFileName
Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (Stopping App)." -Level DEBUG
                Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   toastParamsStopApp.StepName = '$($toastParamsStopApp.StepName)'" -Level DEBUG
                $statusTextForLogStopApp = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsStopApp.StepName)"
                Write-Log -Message "($FunctionName)   Constructed StatusText (Stop App) = '$statusTextForLogStopApp'" -Level DEBUG
                $progressValueForLogStopApp = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
                Write-Log -Message "($FunctionName)   Calculated ProgressValue (Stop App percentage) = $progressValueForLogStopApp %" -Level DEBUG
        $installMode = $WorkflowContext.Params.InstallMode # silent or verysilent

        # Increment step number for the "Install Loxone App" phase before any internal toasts
        $ScriptGlobalState.Value.currentStep++
        Write-Log -Message "($FunctionName) Incremented currentStep to $($ScriptGlobalState.Value.currentStep) for Install App phase." -Level DEBUG

        # App-specific process check/close logic (from original script lines 618-629)
        $appProcessName = $AppTargetInfo.OriginalDetails.ShortcutName # e.g., "Loxone"
        $wasAppRunning = $false
        if (-not [string]::IsNullOrWhiteSpace($appProcessName)) {
            Write-Log -Message "($FunctionName) Checking if Loxone App process '$appProcessName' is running..." -Level DEBUG
            if (Get-ProcessStatus -ProcessName $appProcessName -StopProcess:$false -ErrorAction SilentlyContinue) {
                $wasAppRunning = $true
                Write-Log -Message "($FunctionName) Loxone App process '$appProcessName' is running. Attempting to stop..." -Level INFO
                $toastParamsStopApp = @{ StepNumber = $ScriptGlobalState.Value.currentStep; TotalSteps = $ScriptGlobalState.Value.totalSteps; StepName = "Stopping Loxone App" }
                Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for stopping Loxone App."
                Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-InstallLoxoneApp - Stop App). Initialized: $($Global:PersistentToastInitialized)"
                Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-InstallLoxoneApp - Stop App): toastParamsStopApp='$($toastParamsStopApp | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$([bool]$ScriptGlobalState.Value.anyUpdatePerformed)'")
                Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
                try {
                    Update-PersistentToast @toastParamsStopApp -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                    Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-InstallLoxoneApp - Stop App) called successfully."
                }
                catch {
                    Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-InstallLoxoneApp (Stop App): $($_.Exception.ToString())"
                }
                if (Get-ProcessStatus -ProcessName $appProcessName -StopProcess:$true -ErrorAction SilentlyContinue) {
                    Write-Log -Message "($FunctionName) Successfully requested termination for Loxone App process '$appProcessName'." -Level INFO
                    Start-Sleep -Seconds 2 # Allow time to close
                } else {
                    Write-Log -Message "($FunctionName) Get-ProcessStatus -StopProcess returned false for '$appProcessName'. It might have failed or was already stopped." -Level WARN
                }
            } else {
                Write-Log -Message "($FunctionName) Loxone App process '$appProcessName' is not running." -Level INFO
            }
        } else {
            Write-Log -Message "($FunctionName) Loxone App ShortcutName not available from registry details. Cannot check/stop process by name." -Level WARN
        }

Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (Installing App)." -Level DEBUG
            Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
            Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
            Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
            Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
            Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
            Write-Log -Message "($FunctionName)   toastParamsInstall.StepName = '$($toastParamsInstall.StepName)'" -Level DEBUG
            $statusTextForLogInstallApp = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsInstall.StepName)"
            Write-Log -Message "($FunctionName)   Constructed StatusText (Install App) = '$statusTextForLogInstallApp'" -Level DEBUG
            $progressValueForLogInstallApp = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
            Write-Log -Message "($FunctionName)   Calculated ProgressValue (Install App percentage) = $progressValueForLogInstallApp %" -Level DEBUG
        $toastParamsInstall = @{
            StepNumber        = $ScriptGlobalState.Value.currentStep
            TotalSteps        = $ScriptGlobalState.Value.totalSteps
            StepName          = "$($result.Action)ing Loxone App"
            CurrentWeight     = $ScriptGlobalState.Value.CurrentWeight
            TotalWeight       = $ScriptGlobalState.Value.TotalWeight
            ProgressPercentage = 0           # Reset progress bar for installation phase
            DownloadFileName  = ""           # Clear download-specific fields
            DownloadNumber    = 0
            TotalDownloads    = 0
    }
    Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for Loxone App installation."
    Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-InstallLoxoneApp - Install). Initialized: $($Global:PersistentToastInitialized)"
    Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-InstallLoxoneApp - Install): toastParamsInstall='$($toastParamsInstall | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$([bool]$ScriptGlobalState.Value.anyUpdatePerformed)'")
    Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
    try {
        Update-PersistentToast @toastParamsInstall -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-InstallLoxoneApp - Install) called successfully."
    }
    catch {
        Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-InstallLoxoneApp (Install): $($_.Exception.ToString())"
    }
    $installArgs = "/$installMode" # Typical for InnoSetup installers like Loxone's
    Write-Log -Message "($FunctionName) Executing Loxone App installer: '$appInstallerPath' with arguments '$installArgs'" -Level DEBUG
        $installProcess = Start-Process -FilePath $appInstallerPath -ArgumentList $installArgs -Wait -PassThru -ErrorAction Stop
        Write-Log -Message "($FunctionName) Loxone App installer process exited with code: $($installProcess.ExitCode)" -Level INFO

        if ($installProcess.ExitCode -ne 0) {
            Write-Log -Message "($FunctionName) App Installer returned non-zero exit code: $($installProcess.ExitCode)." -Level WARN
Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (Verifying App Install)." -Level DEBUG
                Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   toastParamsVerify.StepName = '$($toastParamsVerify.StepName)'" -Level DEBUG
                $statusTextForLogVerifyApp = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsVerify.StepName)"
                Write-Log -Message "($FunctionName)   Constructed StatusText (Verify App) = '$statusTextForLogVerifyApp'" -Level DEBUG
                $progressValueForLogVerifyApp = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
                Write-Log -Message "($FunctionName)   Calculated ProgressValue (Verify App percentage) = $progressValueForLogVerifyApp %" -Level DEBUG
Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (Verifying App Install)." -Level DEBUG
                Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   toastParamsVerify.StepName = '$($toastParamsVerify.StepName)'" -Level DEBUG
                $statusTextForLogVerifyApp = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsVerify.StepName)"
                Write-Log -Message "($FunctionName)   Constructed StatusText (Verify App) = '$statusTextForLogVerifyApp'" -Level DEBUG
                $progressValueForLogVerifyApp = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
                Write-Log -Message "($FunctionName)   Calculated ProgressValue (Verify App percentage) = $progressValueForLogVerifyApp %" -Level DEBUG
        }
        $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'InstallApp'
        
        # Verification
Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (App Install Success)." -Level DEBUG
                Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   toastParamsSuccess.StepName = '$($toastParamsSuccess.StepName)'" -Level DEBUG
                $statusTextForLogAppSuccess = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsSuccess.StepName)"
                Write-Log -Message "($FunctionName)   Constructed StatusText (App Success) = '$statusTextForLogAppSuccess'" -Level DEBUG
                $progressValueForLogAppSuccess = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
                Write-Log -Message "($FunctionName)   Calculated ProgressValue (App Success percentage) = $progressValueForLogAppSuccess %" -Level DEBUG
Write-Log -Message "($FunctionName) INVOKE-INSTALLLOXONEAPP: Logging before Update-PersistentToast call (App Install Success)." -Level DEBUG
                Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
                Write-Log -Message "($FunctionName)   toastParamsSuccess.StepName = '$($toastParamsSuccess.StepName)'" -Level DEBUG
                $statusTextForLogAppSuccess = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsSuccess.StepName)"
                Write-Log -Message "($FunctionName)   Constructed StatusText (App Success) = '$statusTextForLogAppSuccess'" -Level DEBUG
                $progressValueForLogAppSuccess = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
                Write-Log -Message "($FunctionName)   Calculated ProgressValue (App Success percentage) = $progressValueForLogAppSuccess %" -Level DEBUG
        Write-Log -Message "($FunctionName) Verifying Loxone App installation..." -Level INFO
        Write-Log -Message "($FunctionName) Verifying Loxone App installation..." -Level INFO
        $toastParamsVerify = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="Verifying Loxone App Installation"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
        Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for Loxone App installation verification."
        Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-InstallLoxoneApp - Verify). Initialized: $($Global:PersistentToastInitialized)"
        Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-InstallLoxoneApp - Verify): toastParamsVerify='$($toastParamsVerify | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$([bool]$ScriptGlobalState.Value.anyUpdatePerformed)'")
        Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
        try {
            Update-PersistentToast @toastParamsVerify -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
            Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-InstallLoxoneApp - Verify) called successfully."
        }
        catch {
            Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-InstallLoxoneApp (Verify): $($_.Exception.ToString())"
        }
        Start-Sleep -Seconds 5 # Allow time for registry updates etc. as in original script
        $newAppDetails = Get-AppVersionFromRegistry -RegistryPath 'HKCU:\Software\3c55ef21-dcba-528f-8e08-1a92f8822a13' -AppNameValueName 'shortcutname' -InstallPathValueName 'InstallLocation' -ErrorAction SilentlyContinue
        
        if ($newAppDetails -and -not $newAppDetails.Error) {
            $result.VersionAfterUpdate = $newAppDetails.FileVersion
            $normalizedNewInstalledApp = Convert-VersionString $newAppDetails.FileVersion
            $normalizedTargetApp = Convert-VersionString $AppTargetInfo.TargetVersion

            if ($normalizedNewInstalledApp -eq $normalizedTargetApp) {
                $result.Succeeded = $true
                Write-Log -Message "($FunctionName) Successfully $($result.Action.ToLower())ed and verified Loxone App to FileVersion $($newAppDetails.FileVersion)." -Level INFO
                $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'VerifyApp' # Assuming a VerifyApp step weight
                $toastParamsSuccess = @{ StepNumber=$ScriptGlobalState.Value.currentStep; TotalSteps=$ScriptGlobalState.Value.totalSteps; StepName="APP v$($newAppDetails.FileVersion)"; CurrentWeight=$ScriptGlobalState.Value.CurrentWeight; TotalWeight=$ScriptGlobalState.Value.TotalWeight }
                Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for successful Loxone App installation."
                Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-InstallLoxoneApp - Success). Initialized: $($Global:PersistentToastInitialized)"
                Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-InstallLoxoneApp - Success): toastParamsSuccess='$($toastParamsSuccess | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$true'")
                Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
                try {
                    Update-PersistentToast @toastParamsSuccess -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed $true -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
                    Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-InstallLoxoneApp - Success) called successfully."
                }
                catch {
                    Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-InstallLoxoneApp (Success): $($_.Exception.ToString())"
                }
Write-Log -Message "($FunctionName) INVOKE-CHECKMINISERVERVERSIONS: Logging before Update-PersistentToast call (MS Check Loop)." -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSLoop.StepName = '$($toastParamsMSLoop.StepName)'" -Level DEBUG
        # Note: DownloadFileName, DownloadNumber, TotalDownloads are not typically used in this specific toast
        $statusTextForLogMSCheck = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSLoop.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Check) = '$statusTextForLogMSCheck'" -Level DEBUG
        $progressValueForLogMSCheck = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Check percentage) = $progressValueForLogMSCheck %" -Level DEBUG
                # Fix the Start Menu shortcut icon after installation
                Write-Log -Message "($FunctionName) Fixing Loxone shortcut icon after installation..." -Level INFO
                try {
                    # Get the executable path from the new app details
                    $exePath = $newAppDetails.InstallLocation
                    if ($exePath -and (Test-Path $exePath)) {
                        # Build shortcut paths dynamically
                        $userProfile = [Environment]::GetFolderPath("UserProfile")
                        $shortcutPath = Join-Path $userProfile "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Loxone.lnk"
                        
                        if (Test-Path $shortcutPath) {
                            # Fix the Start Menu shortcut
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut($shortcutPath)
                            
                            # Update shortcut properties
                            $shortcut.TargetPath = $exePath
                            $shortcut.WorkingDirectory = Split-Path $exePath -Parent
                            $shortcut.IconLocation = "$exePath,0"
                            $shortcut.Description = "Loxone Smart Home App"
                            $shortcut.Save()
                            
                            # Release COM object
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) | Out-Null
                            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
                            
                            Write-Log -Message "($FunctionName) Successfully fixed Start Menu shortcut icon." -Level INFO
                            
                            # Also fix desktop shortcut if it exists
                            $desktopPath = [Environment]::GetFolderPath("Desktop")
                            $desktopShortcut = Join-Path $desktopPath "Loxone.lnk"
                            
                            if (Test-Path $desktopShortcut) {
                                $shell2 = New-Object -ComObject WScript.Shell
                                $desktop = $shell2.CreateShortcut($desktopShortcut)
                                
                                $desktop.TargetPath = $exePath
                                $desktop.WorkingDirectory = Split-Path $exePath -Parent
                                $desktop.IconLocation = "$exePath,0"
                                $desktop.Description = "Loxone Smart Home App"
                                $desktop.Save()
                                
                                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($desktop) | Out-Null
                                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell2) | Out-Null
                                
                                Write-Log -Message "($FunctionName) Also fixed desktop shortcut icon." -Level INFO
                            }
                        } else {
                            Write-Log -Message "($FunctionName) Start Menu shortcut not found at: $shortcutPath" -Level WARN
                        }
                    } else {
                        Write-Log -Message "($FunctionName) Loxone executable not found for icon fix." -Level WARN
                    }
                } catch {
                    Write-Log -Message "($FunctionName) Error fixing shortcut icon: $($_.Exception.Message)" -Level WARN
                    # Non-critical error, continue with the process
                }
                
                # Restart app if it was running (original script lines 695-709)
                if ($wasAppRunning -and -not [string]::IsNullOrWhiteSpace($newAppDetails.InstallLocation)) {
                    Write-Log -Message  "($FunctionName) Loxone App was running before update. Attempting restart of '$($newAppDetails.InstallLocation)'..." -Level INFO
                    # This restart logic might also need to consider SYSTEM vs User context if the main script isn't always user.
                    # For simplicity, using Start-Process. Invoke-AsCurrentUser might be needed if script runs as SYSTEM.
                    try {
                        Start-Process -FilePath $newAppDetails.InstallLocation -WindowStyle Minimized -ErrorAction Stop
                        Write-Log -Message "($FunctionName) Loxone App restart command issued." -Level INFO
                    } catch {
                         Write-Log -Message "($FunctionName) Failed to restart Loxone App: $($_.Exception.Message)" -Level ERROR
Write-Log -Message "($FunctionName) INVOKE-CHECKMINISERVERVERSIONS: Logging before Update-PersistentToast call (MS Check Loop)." -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSLoop.StepName = '$($toastParamsMSLoop.StepName)'" -Level DEBUG
        # Note: DownloadFileName, DownloadNumber, TotalDownloads are not typically used in this specific toast
        $statusTextForLogMSCheck = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSLoop.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Check) = '$statusTextForLogMSCheck'" -Level DEBUG
        $progressValueForLogMSCheck = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Check percentage) = $progressValueForLogMSCheck %" -Level DEBUG
                    }
                }

            } else {
                $result.Reason = "VerificationFailed"
                $errorMsg = "Loxone App update verification failed! Expected FileVersion '$normalizedTargetApp' but found '$normalizedNewInstalledApp'."
                if ($installProcess.ExitCode -ne 0) {
                    $errorMsg += " Installer also exited with code $($installProcess.ExitCode)."
                    $result.Reason = "InstallFailedAndVerificationFailed"
                }
                Write-Log -Message "($FunctionName) $errorMsg" -Level ERROR
                throw $errorMsg
            }
        } else {
            $result.Reason = "RegistryReadErrorAfterInstall"
            $errorMsg = "Failed to get Loxone App details from registry after installation attempt. Error: $($newAppDetails.Error)"
            Write-Log -Message "($FunctionName) $errorMsg" -Level ERROR
            throw $errorMsg
        }

    } catch {
        $result.Succeeded = $false
        if ([string]::IsNullOrWhiteSpace($result.Reason)) {
            $result.Reason = "InstallException"
        }
        $result.Error = $_
        Write-Log -Message "($FunctionName) Exception during Loxone App installation/verification: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    }
    return $result
}
function Invoke-CheckMiniserverVersions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext, # Contains MSListPath, Params (for SkipCertificateCheck, DebugMode), etc.
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Prerequisites, # Contains LatestConfigVersionNormalized (target version for MS)
        [Parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$UpdateTargetsToUpdate, # The main $UpdateTargetsInfo array from UpdateLoxone.ps1, passed to be MODIFIED
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    # Entry and Parameters Logging
    Write-Log -Level DEBUG -Message "Entering function '$($FunctionName)'."
    Write-Log -Level DEBUG -Message "Parameters for '$($FunctionName)':"
    Write-Log -Level DEBUG -Message "  WorkflowContext.MSListPath: '$($WorkflowContext.MSListPath)'"
    Write-Log -Level DEBUG -Message "  WorkflowContext.Params.EnforceSSLCertificate: '$($WorkflowContext.Params.EnforceSSLCertificate)'"
    Write-Log -Level DEBUG -Message "  WorkflowContext.Params.DebugMode: '$($WorkflowContext.Params.DebugMode)'"
    Write-Log -Level DEBUG -Message "  Prerequisites.LatestConfigVersionNormalized (Target Version for MS): '$($Prerequisites.LatestConfigVersionNormalized)'"
    Write-Log -Level DEBUG -Message "  UpdateTargetsToUpdate.Count (Initial): '$($UpdateTargetsToUpdate.Count)'"
    # Note: ScriptGlobalState is a [ref] object, logging its value directly might be too verbose or complex here.
    # Logging specific relevant parts of ScriptGlobalState if needed.

    $overallResult = [pscustomobject]@{
        Succeeded = $true # Overall success of the checking process, not individual MS
        Reason    = ""    # Add Reason property for consistency with other steps
        Error     = $null
        Component = "MiniserverCheck"
        Action    = "VersionCheck"
        CheckedCount = 0
        NeedsUpdateCount = 0
    }
    Write-Log -Message "($FunctionName) Starting Miniserver version checks." -Level INFO

    # Find the Config target to get the authoritative target version for Miniservers
    $configTarget = $UpdateTargetsToUpdate | Where-Object {$_.Type -eq "Config"} | Select-Object -First 1
    $targetMSVersion = $null
    if ($configTarget -and $configTarget.TargetVersion) {
        $targetMSVersion = $configTarget.TargetVersion # This should be the normalized version
        Write-Log -Message "($FunctionName) Target Miniserver version (from Config target): $targetMSVersion" -Level DEBUG
    } else {
        Write-Log -Message "($FunctionName) Could not determine target Miniserver version from Config target in UpdateTargetsInfo. Using LatestConfigVersionNormalized from Prerequisites: $($Prerequisites.LatestConfigVersionNormalized)." -Level WARN
        $targetMSVersion = $Prerequisites.LatestConfigVersionNormalized
    }

    if (-not $targetMSVersion) {
        $overallResult.Succeeded = $false
        $overallResult.Reason = "NoTargetMSVersion"
        $msg = "($FunctionName) CRITICAL: Cannot determine target version for Miniservers. Config target version is missing."
        Write-Log -Message $msg -Level ERROR
        $overallResult.Error = $msg
        return $overallResult
    }

    $msEntriesToProcess = $UpdateTargetsToUpdate | Where-Object {$_.Type -eq "Miniserver"}
    if ($msEntriesToProcess.Count -eq 0) {
        Write-Log -Message "($FunctionName) No Miniserver entries found in UpdateTargetsToUpdate. Skipping MS version check." -Level INFO
        return $overallResult # Succeeded = $true, but 0 checked
    }

    Write-Log -Message "($FunctionName) Checking $($msEntriesToProcess.Count) Miniserver(s) against target version $targetMSVersion..." -Level INFO
    $ScriptGlobalState.Value.currentStep++ # Increment step for the overall MS checking phase

    $msCheckedCounter = 0
    foreach ($msPlaceholderTarget in $msEntriesToProcess) {
Write-Log -Message "($FunctionName) INVOKE-UPDATEMINISERVERSINBULK: Logging before Update-PersistentToast call (Bulk MS Update Start)." -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSUpdateStart.StepName = '$($toastParamsMSUpdateStart.StepName)'" -Level DEBUG
        $statusTextForLogMSBulk = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSUpdateStart.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Bulk Update) = '$statusTextForLogMSBulk'" -Level DEBUG
        $progressValueForLogMSBulk = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Bulk Update percentage) = $progressValueForLogMSBulk %" -Level DEBUG
Write-Log -Message "($FunctionName) INVOKE-UPDATEMINISERVERSINBULK: Logging before Update-PersistentToast call (Bulk MS Update Start)." -Level DEBUG
Write-Log -Message "($FunctionName) INVOKE-UPDATEMINISERVERSINBULK: Logging before Update-PersistentToast call (Bulk MS Update Start)." -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSUpdateStart.StepName = '$($toastParamsMSUpdateStart.StepName)'" -Level DEBUG
        $statusTextForLogMSBulkStart = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSUpdateStart.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Bulk Update Start) = '$statusTextForLogMSBulkStart'" -Level DEBUG
        $progressValueForLogMSBulkStart = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Bulk Update Start percentage) = $progressValueForLogMSBulkStart %" -Level DEBUG
Write-Log -Message "($FunctionName) INVOKE-UPDATEMINISERVERSINBULK: Logging before Update-PersistentToast call (Bulk MS Update Start)." -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSUpdateStart.StepName = '$($toastParamsMSUpdateStart.StepName)'" -Level DEBUG
        $statusTextForLogMSBulk = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSUpdateStart.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Bulk Update) = '$statusTextForLogMSBulk'" -Level DEBUG
        $progressValueForLogMSBulk = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Bulk Update percentage) = $progressValueForLogMSBulk %" -Level DEBUG
        Write-Log -Message "($FunctionName)   Global:PersistentToastInitialized = $($Global:PersistentToastInitialized)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName)   toastParamsMSUpdateStart.StepName = '$($toastParamsMSUpdateStart.StepName)'" -Level DEBUG
        $statusTextForLogMSBulk = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsMSUpdateStart.StepName)"
        Write-Log -Message "($FunctionName)   Constructed StatusText (MS Bulk Update) = '$statusTextForLogMSBulk'" -Level DEBUG
        $progressValueForLogMSBulk = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
        Write-Log -Message "($FunctionName)   Calculated ProgressValue (MS Bulk Update percentage) = $progressValueForLogMSBulk %" -Level DEBUG
        $msCheckedCounter++
        $overallResult.CheckedCount++
        
        $msEntryForLog = Get-RedactedPassword $msPlaceholderTarget.OriginalEntry

        $toastParamsMSLoop = @{
            StepNumber    = $ScriptGlobalState.Value.currentStep
            TotalSteps    = $ScriptGlobalState.Value.totalSteps
            StepName      = "Checking MS $msCheckedCounter/$($msEntriesToProcess.Count): $($msPlaceholderTarget.Name)"
            CurrentWeight = $ScriptGlobalState.Value.CurrentWeight # Weight for this step is added after all checks
            TotalWeight   = $ScriptGlobalState.Value.TotalWeight
    }
    Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for MS check loop start: $($msPlaceholderTarget.Name)."
    Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for MS check loop start: $($msPlaceholderTarget.Name)."
    Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-CheckMiniserverVersions - Loop Start). Initialized: $($Global:PersistentToastInitialized)"
    Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-CheckMiniserverVersions - Loop Start): toastParamsMSLoop='$($toastParamsMSLoop | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$([bool]$ScriptGlobalState.Value.anyUpdatePerformed)'")
    Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
    try {
        Update-PersistentToast @toastParamsMSLoop -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-CheckMiniserverVersions - Loop Start) called successfully."
    }
    catch {
        Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-CheckMiniserverVersions (Loop Start): $($_.Exception.ToString())"
    }
    Write-Log -Message "($FunctionName) Processing MS entry $msCheckedCounter/$($msEntriesToProcess.Count): $msEntryForLog" -Level INFO
        Write-Log -Level DEBUG -Message "  ($FunctionName)   OriginalEntry (redacted for log): '$($msPlaceholderTarget.OriginalEntry -replace "([Pp]assword=)[^;]+", '$1********')'" # URL is part of OriginalEntry
        Write-Log -Level DEBUG -Message "  ($FunctionName)   EnforceSSLCertificate: '$($WorkflowContext.Params.EnforceSSLCertificate)'"
        Write-Log -Level DEBUG -Message "  ($FunctionName)   TimeoutSec: 5"
        
        # Skip certificate check by default unless EnforceSSLCertificate is specified
        $skipCert = -not $WorkflowContext.Params.EnforceSSLCertificate
        
        # First try original method
        $msVersionInfo = Get-MiniserverVersion -MSEntry $msPlaceholderTarget.OriginalEntry -SkipCertificateCheck:$skipCert -TimeoutSec 5 -ErrorAction SilentlyContinue
        
        # If HTTPS fails, try HTTP fallback only for SSL/TLS errors, not connectivity issues
        if ($msVersionInfo.Error -and $msPlaceholderTarget.OriginalEntry -match '^https://') {
            # Only try HTTP fallback for SSL/TLS errors, not timeouts or connectivity issues
            if ($msVersionInfo.Error -match 'SSL|TLS|certificate|Unerwarteter Fehler beim Senden|underlying connection was closed' -and 
                $msVersionInfo.Error -notmatch 'Zeitlimit|Timeout|timed out|cannot be resolved|host is unknown') {
                Write-Log -Level INFO -Message "  ($FunctionName) HTTPS failed with SSL/TLS error for '$($msPlaceholderTarget.Name)', attempting HTTP fallback..."
                $httpEntry = $msPlaceholderTarget.OriginalEntry -replace '^https://', 'http://'
                $httpVersionInfo = Get-MiniserverVersion -MSEntry $httpEntry -SkipCertificateCheck:$skipCert -TimeoutSec 5 -ErrorAction SilentlyContinue
                
                if (-not $httpVersionInfo.Error) {
                    Write-Log -Level INFO -Message "  ($FunctionName) HTTP fallback succeeded for '$($msPlaceholderTarget.Name)'"
                    $msVersionInfo = $httpVersionInfo
                    # Update the entry to use HTTP for future operations
                    $msPlaceholderTarget.OriginalEntry = $httpEntry
                } else {
                    Write-Log -Level WARN -Message "  ($FunctionName) HTTP fallback also failed for '$($msPlaceholderTarget.Name)'"
                }
            } else {
                Write-Log -Level INFO -Message "  ($FunctionName) Connection failed due to timeout/connectivity issue for '$($msPlaceholderTarget.Name)' - not attempting HTTP fallback"
            }
        }

        # Log result from Get-MiniserverVersion
        if ($msVersionInfo.Error) {
            Write-Log -Level WARN -Message "  ($FunctionName) Get-MiniserverVersion for '$($msPlaceholderTarget.Name)' returned an error: $($msVersionInfo.Error)"
            Write-Log -Level DEBUG -Message "  ($FunctionName) Full error details from Get-MiniserverVersion for '$($msPlaceholderTarget.Name)': $($msVersionInfo.Error | Out-String)"
            $msPlaceholderTarget.InitialVersion = "ErrorConnecting"
            $msPlaceholderTarget.Status = "ErrorConnecting"
            $msPlaceholderTarget.UpdateNeeded = $true # Assume update needed if can't connect to check
            $overallResult.NeedsUpdateCount++
            continue
        continue
    }
    Write-Log -Level DEBUG -Message "  ($FunctionName) Get-MiniserverVersion for '$($msPlaceholderTarget.Name)' returned Version: '$($msVersionInfo.Version)' (Raw object: $($msVersionInfo | ConvertTo-Json -Depth 2 -Compress))"

    $msPlaceholderTarget.InitialVersion = $msVersionInfo.Version
    $normalizedCurrentMSVersion = Convert-VersionString $msVersionInfo.Version
        Write-Log -Message "($FunctionName) MS '$($msPlaceholderTarget.Name)' current version: $($msVersionInfo.Version) (Normalized: $normalizedCurrentMSVersion)" -Level INFO

        if ($normalizedCurrentMSVersion -ne $targetMSVersion) {
            if ([Version]$normalizedCurrentMSVersion -lt [Version]$targetMSVersion) {
                Write-Log -Message "($FunctionName) MS '$($msPlaceholderTarget.Name)' version '$normalizedCurrentMSVersion' is older than target '$targetMSVersion'. Update needed." -Level INFO
                $msPlaceholderTarget.UpdateNeeded = $true
                $msPlaceholderTarget.Status = "NeedsUpdate"
                $overallResult.NeedsUpdateCount++
            } else { # Current is newer
                Write-Log -Message "($FunctionName) MS '$($msPlaceholderTarget.Name)' version '$normalizedCurrentMSVersion' is newer than target '$targetMSVersion'. No update." -Level INFO
                $msPlaceholderTarget.UpdateNeeded = $false
                $msPlaceholderTarget.Status = "NewerThanTarget"
            }
        } else {
            Write-Log -Message "($FunctionName) MS '$($msPlaceholderTarget.Name)' is already at target version '$targetMSVersion'." -Level INFO
            $msPlaceholderTarget.UpdateNeeded = $false
            $msPlaceholderTarget.Status = "UpToDate"
        }
    }

    # Add weight for the "CheckMSVersions" step itself
    $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'CheckMSVersions'
    Write-Log -Message "($FunctionName) Finished checking Miniserver versions. Found $($overallResult.NeedsUpdateCount) needing update out of $($overallResult.CheckedCount) checked." -Level INFO
    
    # Check if any MS had connection errors
    Write-Log -Message "($FunctionName) DEBUG: Checking for miniserver connection errors..." -Level DEBUG
    $msWithErrors = @($UpdateTargetsToUpdate | Where-Object {$_.Type -eq "Miniserver" -and $_.Status -eq "ErrorConnecting"})
    Write-Log -Message "($FunctionName) DEBUG: UpdateTargetsToUpdate count: $($UpdateTargetsToUpdate.Count)" -Level DEBUG
    Write-Log -Message "($FunctionName) DEBUG: Miniservers with ErrorConnecting: $($msWithErrors.Count)" -Level DEBUG
    if ($msWithErrors -and $msWithErrors.Count -gt 0) {
        $msWithErrors | ForEach-Object {
            Write-Log -Message "($FunctionName) DEBUG: MS with error: $($_.Name), Status: $($_.Status)" -Level DEBUG
        }
    }
    
    # Force the count to be an integer
    $connectionErrorCount = [int]$msWithErrors.Count
    Write-Log -Message "($FunctionName) DEBUG: Connection error count (as int): $connectionErrorCount" -Level DEBUG
    
    if ($connectionErrorCount -gt 0) {
        $overallResult.Succeeded = $false
        $overallResult.Reason = "MiniserverConnectionErrors"
        $overallResult.Error = "$connectionErrorCount Miniserver(s) had connection errors"
        Write-Log -Message "($FunctionName) ERROR: $connectionErrorCount Miniserver(s) failed to connect. Setting result as failed." -Level ERROR
        Write-Log -Message "($FunctionName) DEBUG: Set overallResult.Succeeded = $($overallResult.Succeeded), Reason = $($overallResult.Reason)" -Level DEBUG
    } else {
        Write-Log -Message "($FunctionName) DEBUG: No miniserver connection errors found" -Level DEBUG
    }
    
Write-Log -Message "($FunctionName) INVOKE-CHECKMINISERVERVERSIONS: After adding weight for 'CheckMSVersions' step." -Level DEBUG
    Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentStepNumber = $($ScriptGlobalState.Value.currentStep)" -Level DEBUG
    Write-Log -Message "($FunctionName)   scriptGlobalState.TotalStepsForUI = $($ScriptGlobalState.Value.totalSteps)" -Level DEBUG
    Write-Log -Message "($FunctionName)   scriptGlobalState.CurrentWeight = $($ScriptGlobalState.Value.CurrentWeight)" -Level DEBUG
    Write-Log -Message "($FunctionName)   scriptGlobalState.TotalWeight = $($ScriptGlobalState.Value.TotalWeight)" -Level DEBUG

$ScriptGlobalState.Value.currentStep++ # Increment UI step before showing "Checks Completed"
    Write-Log -Message "($FunctionName) INVOKE-CHECKMINISERVERVERSIONS: Incremented currentStep for UI to $($ScriptGlobalState.Value.currentStep) before 'Checks Completed' toast." -Level DEBUG
    # Update toast to reflect completion of MS checks
    $toastParamsPostMSCheck = @{
        StepNumber    = $ScriptGlobalState.Value.currentStep
        TotalSteps    = $ScriptGlobalState.Value.totalSteps
        StepName      = "Miniserver Version Checks Completed"
        CurrentWeight = $ScriptGlobalState.Value.CurrentWeight
        TotalWeight   = $ScriptGlobalState.Value.TotalWeight
    }
    Write-Log -Message "($FunctionName) INVOKE-CHECKMINISERVERVERSIONS: Logging before Update-PersistentToast call (Post MS Check Loop)." -Level DEBUG
    $statusTextForLogPostMS = "Step $($ScriptGlobalState.Value.currentStep)/$($ScriptGlobalState.Value.totalSteps): $($toastParamsPostMSCheck.StepName)"
    Write-Log -Message "($FunctionName)   Constructed StatusText (Post MS Check) = '$statusTextForLogPostMS'" -Level DEBUG
    $progressValueForLogPostMS = if ($ScriptGlobalState.Value.TotalWeight -gt 0) { [Math]::Round(($ScriptGlobalState.Value.CurrentWeight / $ScriptGlobalState.Value.TotalWeight) * 100) } else { 0 }
    Write-Log -Message "($FunctionName)   Calculated ProgressValue (Post MS Check percentage) = $progressValueForLogPostMS %" -Level DEBUG
    
    try {
        Update-PersistentToast @toastParamsPostMSCheck -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Post MS Check Loop) called successfully."
    }
    catch {
        Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-CheckMiniserverVersions (Post MS Check Loop): $($_.Exception.ToString())"
    }
    return $overallResult
}
function Invoke-UpdateMiniserversInBulk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext, # For MSListPath, DebugMode, SkipCertificateCheck, LoxoneIconPath etc.
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Prerequisites,   # For LatestConfigVersionNormalized (Target MS Version)
        [Parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$UpdateTargetsToUpdate, # The main $UpdateTargetsInfo array
        [Parameter(Mandatory=$true)]
        [ref]$ScriptGlobalState,
        [Parameter(Mandatory=$true)] # Added
        [string]$ConfiguredUpdateChannel # Added
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    $overallResult = [pscustomobject]@{
        Succeeded        = $true # Assume overall success unless a specific MS update fails catastrophically or Update-MS fails
        Reason           = ""
        Error            = $null
        Component        = "MiniserverUpdate"
        Action           = "BulkUpdate"
        UpdatedCount     = 0
        FailedCount      = 0
        SkippedCount     = 0 # e.g. if already up to date from a re-check inside Update-MS
        TotalConsidered  = 0
    }
    Write-Log -Message "($FunctionName) Starting bulk Miniserver update process." -Level INFO

    $miniserversThatNeedUpdate = $UpdateTargetsToUpdate | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded -eq $true -and $_.Status -ne "ErrorConnecting" -and $_.Status -ne "ErrorProcessingEntry"}
    $overallResult.TotalConsidered = $miniserversThatNeedUpdate.Count

    if ($miniserversThatNeedUpdate.Count -eq 0) {
        Write-Log -Message "($FunctionName) No Miniservers marked as needing an update. Skipping bulk update." -Level INFO
        # Add weight for the UpdateMS step itself, even if no MS are updated, as the step "ran"
        $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'UpdateMS' # Base weight for the step
        return $overallResult
    }

    $targetMSVersion = $Prerequisites.LatestConfigVersionNormalized
    if (-not $targetMSVersion) {
        # This should have been caught by Invoke-CheckMiniserverVersions, but as a safeguard:
        $overallResult.Succeeded = $false; $overallResult.Reason = "NoTargetMSVersionForUpdate"
        Write-Log -Message "($FunctionName) CRITICAL: Target version for MS update is not defined." -Level ERROR
        return $overallResult
    }
    
    # Don't increment currentStep here - it causes the "step 3/2" issue
    # The step counter is already managed by the main pipeline loop
    $toastParamsMSUpdateStart = @{
        StepNumber    = $ScriptGlobalState.Value.currentStep
        TotalSteps    = $ScriptGlobalState.Value.totalSteps
        StepName      = "Updating $($miniserversThatNeedUpdate.Count) Miniserver(s)..."
        CurrentWeight = $ScriptGlobalState.Value.CurrentWeight
        TotalWeight   = $ScriptGlobalState.Value.TotalWeight
    }
    Write-Log -Level DEBUG -Message "($FunctionName) Intent: Update toast for starting bulk MS update."
    Write-Log -Level DEBUG -Message "($FunctionName) Attempting to update progress toast (Invoke-UpdateMiniserversInBulk - Update Start). Initialized: $($Global:PersistentToastInitialized)"
    Write-Log -Level DEBUG -Message ("($FunctionName) Params for Update-PersistentToast (Invoke-UpdateMiniserversInBulk - Update Start): toastParamsMSUpdateStart='$($toastParamsMSUpdateStart | Out-String)', IsInteractive='$([bool]$WorkflowContext.IsInteractive)', ErrorOccurred='$([bool]$ScriptGlobalState.Value.ErrorOccurred)', AnyUpdatePerformed='$([bool]$ScriptGlobalState.Value.anyUpdatePerformed)'")
    Write-Log -Level DEBUG -Message ("($FunctionName) Current scriptGlobalState: StepNumber='$($ScriptGlobalState.Value.currentStep)', TotalSteps='$($ScriptGlobalState.Value.totalSteps)', CurrentWeight='$($ScriptGlobalState.Value.CurrentWeight)', TotalWeight='$($ScriptGlobalState.Value.TotalWeight)'")
    try {
        Update-PersistentToast @toastParamsMSUpdateStart -IsInteractive ([bool]$WorkflowContext.IsInteractive) -ErrorOccurred ([bool]$ScriptGlobalState.Value.ErrorOccurred) -AnyUpdatePerformed ([bool]$ScriptGlobalState.Value.anyUpdatePerformed) -CallingScriptIsInteractive ([bool]$WorkflowContext.IsInteractive) -CallingScriptIsSelfInvoked ([bool]$WorkflowContext.IsSelfInvokedForUpdateCheck)
        Write-Log -Level DEBUG -Message "($FunctionName) Update-PersistentToast (Invoke-UpdateMiniserversInBulk - Update Start) called successfully."
    }
    catch {
        Write-Log -Level ERROR -Message "($FunctionName) ERROR during Update-PersistentToast call in Invoke-UpdateMiniserversInBulk (Update Start): $($_.Exception.ToString())"
    }
    # The Update-MS function from LoxoneUtils.Miniserver.psm1 handles a list of MS entries
    # by reading the MSListPath file. $WorkflowContext.MSListPath is passed directly.
    # $msEntriesToPassToUpdateMS = $miniserversThatNeedUpdate.OriginalEntry # This line is no longer needed as MSListPath is used
    
    # The LoxoneConfigExePathForMSUpdate should be determined in the main script
    # and passed via WorkflowContext or directly if this function's scope needs it.
    # For now, assuming it's in $WorkflowContext.InstalledConfigExePath (after Config update)
    $loxoneConfigExeToUse = $WorkflowContext.InstalledConfigExePath
    if (-not (Test-Path $loxoneConfigExeToUse)) {
        Write-Log -Message "($FunctionName) Loxone Config EXE path '$loxoneConfigExeToUse' not found. MS Update cannot proceed using it." -Level ERROR
        # Attempt to use the initially detected path if available and different
        if ($WorkflowContext.InitialInstalledConfigVersion -and $WorkflowContext.InstalledConfigExePath -and $WorkflowContext.InstalledConfigExePath -ne $loxoneConfigExeToUse) {
            Write-Log -Message "($FunctionName) Attempting to use initially detected Loxone Config path: '$($WorkflowContext.InstalledConfigExePath)'" -Level WARN
            $loxoneConfigExeToUse = $WorkflowContext.InstalledConfigExePath
        }
        if (-not (Test-Path $loxoneConfigExeToUse)) {
             $overallResult.Succeeded = $false; $overallResult.Reason = "ConfigExeNotFoundForMSUpdate"
             Write-Log -Message "($FunctionName) CRITICAL: Loxone Config executable not found at '$loxoneConfigExeToUse'. Cannot perform Miniserver updates." -Level ERROR
             return $overallResult
        }
    }


    $updateMSParams = @{
        MSListPath                    = $WorkflowContext.MSListPath # Path to the file containing MS entries
        DesiredVersion                = $targetMSVersion
        ConfiguredUpdateChannel       = $ConfiguredUpdateChannel # Added
        LogFile                       = $WorkflowContext.LogFile
        MaxLogFileSizeMB              = $WorkflowContext.Params.MaxLogFileSizeMB
        ScriptSaveFolder              = $WorkflowContext.ScriptSaveFolder # For temp files Update-MS might use
        SkipCertificateCheck          = -not $WorkflowContext.Params.EnforceSSLCertificate
        IsInteractive                 = $WorkflowContext.IsInteractive
        StepNumber                    = $ScriptGlobalState.Value.currentStep # Pass current overall step
        TotalSteps                    = $ScriptGlobalState.Value.totalSteps    # Pass total overall steps
        ErrorAction                   = 'Continue' # Update-MS handles its own errors per MS and returns a summary
    }
    if ($WorkflowContext.Params.DebugMode) { $updateMSParams.DebugMode = $true }

    try {
        $updateResultsFromUpdateMS = Update-MS @updateMSParams
        
        # Process results from Update-MS and update $UpdateTargetsToUpdate
        if ($null -ne $updateResultsFromUpdateMS) {
            foreach ($msResult in $updateResultsFromUpdateMS) {
                $msTargetToUpdate = $UpdateTargetsToUpdate | Where-Object {$_.Type -eq "Miniserver" -and $_.OriginalEntry -eq $msResult.MSEntry} | Select-Object -First 1
                if ($msTargetToUpdate) {
                    $msTargetToUpdate.VersionAfterUpdate = $msResult.VersionAfterUpdate
                    $msTargetToUpdate.UpdatePerformed = $msResult.AttemptedUpdate
                    $msTargetToUpdate.Status = $msResult.StatusMessage # StatusMessage from Update-MS should be one of the standard ones
                    
                    if ($msResult.UpdateSucceeded) {
                        $overallResult.UpdatedCount++
                        $ScriptGlobalState.Value.anyUpdatePerformed = $true
                    } elseif ($msResult.StatusMessage -eq "AlreadyUpToDate" -or $msResult.StatusMessage -eq "NewerThanTarget") {
                        $overallResult.SkippedCount++
                        $msTargetToUpdate.UpdatePerformed = $false # Ensure it's false if skipped
                    } else {
                        $overallResult.FailedCount++
                        # $overallResult.Succeeded = $false # Commented: One MS failure doesn't mean the whole step failed, but it's not a full success
                    }
                }
                $ScriptGlobalState.Value.CurrentWeight += 2 # Add weight per MS processed by Update-MS (assuming weight of 2 per MS)
            }
        }
        if ($overallResult.FailedCount -gt 0) {
            $overallResult.Succeeded = $false # Mark overall step as not fully successful if any MS failed
            $overallResult.Reason = "OneOrMoreMSUpdatesFailed"
        }

    } catch {
        $overallResult.Succeeded = $false
        $overallResult.Reason = "BulkMSUpdateException"
        $overallResult.Error = $_
        Write-Log -Message "($FunctionName) Exception during bulk Miniserver update call: $($_.Exception.Message)" -Level ERROR
        Write-Log -Message "($FunctionName) Full Error Record: ($($_ | Out-String))" -Level DEBUG
    }
    
    # Add base weight for the UpdateMS step itself, regardless of how many MS were updated (as long as the step ran)
    $ScriptGlobalState.Value.CurrentWeight += Get-StepWeight -StepID 'UpdateMS' 
    $ScriptGlobalState.Value.CurrentWeight = [Math]::Min($ScriptGlobalState.Value.CurrentWeight, $ScriptGlobalState.Value.TotalWeight) # Cap at total

    Write-Log -Message "($FunctionName) Finished Miniserver bulk update. Updated: $($overallResult.UpdatedCount), Failed: $($overallResult.FailedCount), Skipped: $($overallResult.SkippedCount) out of $($overallResult.TotalConsidered) considered." -Level INFO
    return $overallResult
}
# Functions for actual update workflows will be added later:
# Invoke-LoxoneConfigUpdateWorkflow
# Invoke-LoxoneAppUpdateWorkflow
# Invoke-LoxoneMiniserverUpdateWorkflow

function Initialize-UpdatePipelineData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$WorkflowContext, # Contains initial versions, params, paths, MSListPath etc.

        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Prerequisites    # Output from Get-LoxoneUpdatePrerequisites
    )
    $FunctionName = $MyInvocation.MyCommand.Name
    Write-Log -Message "($FunctionName) Initializing update pipeline data (targets, weights, steps)..." -Level INFO

    $pipelineData = [pscustomobject]@{
        Succeeded         = $true
        Reason            = ""
        Error             = $null
        Component         = "PipelineDataInitialization"
        UpdateTargetsInfo = [System.Collections.ArrayList]::new()
        TotalWeight       = 0
        TotalSteps        = 0
        TotalDownloads    = 0
        InitialCheckWeight = 0
    }

    try { # Main try for the entire function
        # --- Populate UpdateTargetsInfo based on prerequisites ---
        # Config Target
        $configTargetEntry = [PSCustomObject]@{
            Name                = "Conf"
            Type                = "Config"
            InitialVersion      = $WorkflowContext.InitialInstalledConfigVersion
            TargetVersion       = $Prerequisites.LatestConfigVersionNormalized
            UpdateNeeded        = $Prerequisites.ConfigUpdateNeeded
            Status              = if ($Prerequisites.ConfigUpdateNeeded) { "NeedsUpdate" } elseif ($WorkflowContext.InitialInstalledConfigVersion) { "UpToDate" } else { "NotInstalled" }
            UpdatePerformed     = $false
            VersionAfterUpdate  = $null
            DownloadUrl         = $Prerequisites.ConfigZipUrl
            ExpectedSize        = $Prerequisites.ConfigExpectedZipSize
            ExpectedCRC         = $Prerequisites.ConfigExpectedCRC
            ZipFileName         = $Prerequisites.ConfigZipFileName
            InstallerFileName   = $Prerequisites.ConfigInstallerFileName
            ZipFilePath         = Join-Path -Path $WorkflowContext.DownloadDir -ChildPath $Prerequisites.ConfigZipFileName
            InstallerPath       = Join-Path -Path $WorkflowContext.DownloadDir -ChildPath $Prerequisites.ConfigInstallerFileName
            Channel             = $WorkflowContext.Params.Channel
        }
        $pipelineData.UpdateTargetsInfo.Add($configTargetEntry) | Out-Null
        Write-Log -Message "($FunctionName) [UpdateTargets] Added Loxone Config: Name='$($configTargetEntry.Name)', Initial='$($configTargetEntry.InitialVersion)', Target='$($configTargetEntry.TargetVersion)', UpdateNeeded='$($configTargetEntry.UpdateNeeded)', Status='$($configTargetEntry.Status)'" -Level DEBUG

        # App Target
        Write-Log -Message "($FunctionName) [AppTargetCheck_DEBUG] BEFORE if condition for App Target." -Level DEBUG
        # Determine the effective boolean value for UpdateLoxoneApp, considering its default
        $shouldAddAppTarget = $false
        if ($WorkflowContext.Params.ContainsKey('UpdateLoxoneApp')) {
            $shouldAddAppTarget = [bool]$WorkflowContext.Params.UpdateLoxoneApp
            Write-Log -Message "($FunctionName) [AppTargetCheck_DEBUG] UpdateLoxoneApp key FOUND in Params. Value: '$($WorkflowContext.Params.UpdateLoxoneApp)', Effective Bool: '$shouldAddAppTarget'." -Level DEBUG
        } else {
            $shouldAddAppTarget = $true # Default value of UpdateLoxoneApp parameter in UpdateLoxone.ps1
            Write-Log -Message "($FunctionName) [AppTargetCheck_DEBUG] UpdateLoxoneApp key NOT FOUND in Params. Using default: '$shouldAddAppTarget'." -Level DEBUG
        }

        if ($shouldAddAppTarget) {
            Write-Log -Message "($FunctionName) [AppTargetCheck_DEBUG] INSIDE if condition for App Target (condition was true based on effective value)." -Level DEBUG
            $appInitialVersionFromFile = $null
            if ($WorkflowContext.InitialLoxoneAppDetails) {
                $appInitialVersionFromFile = $WorkflowContext.InitialLoxoneAppDetails.FileVersion
                Write-Log -Message "($FunctionName) [AppTargetCheck] InitialLoxoneAppDetails is NOT NULL. appInitialVersionFromFile set to: '$appInitialVersionFromFile'" -Level DEBUG
            } else {
                Write-Log -Message "($FunctionName) [AppTargetCheck] InitialLoxoneAppDetails IS NULL. appInitialVersionFromFile remains null." -Level DEBUG
            }
            
            $appTargetEntry = [PSCustomObject]@{
                Name                = "APP"
                Type                = "App"
                InitialVersion      = $appInitialVersionFromFile
                TargetVersion       = $Prerequisites.LatestAppVersion
                UpdateNeeded        = $Prerequisites.AppUpdateNeeded
                Status              = if ($Prerequisites.AppUpdateNeeded) { "NeedsUpdate" } elseif ($appInitialVersionFromFile) { "UpToDate" } else { "NotInstalled" }
                UpdatePerformed     = $false
                VersionAfterUpdate  = $null
                DownloadUrl         = $Prerequisites.AppInstallerUrl
                ExpectedSize        = $Prerequisites.AppExpectedSize
                ExpectedCRC         = $Prerequisites.AppExpectedCRC
                InstallerFileName   = $Prerequisites.AppInstallerFileName
                InstallerPath       = Join-Path -Path $WorkflowContext.DownloadDir -ChildPath $Prerequisites.AppInstallerFileName
                Channel             = $Prerequisites.SelectedAppChannelName
                OriginalDetails     = $WorkflowContext.InitialLoxoneAppDetails
            }
            $pipelineData.UpdateTargetsInfo.Add($appTargetEntry) | Out-Null
            Write-Log -Message "($FunctionName) [UpdateTargets] Added Loxone App: Name='$($appTargetEntry.Name)', Initial='$($appTargetEntry.InitialVersion)', Target='$($appTargetEntry.TargetVersion)', UpdateNeeded='$($appTargetEntry.UpdateNeeded)', Status='$($appTargetEntry.Status)'" -Level DEBUG
        }

        # Miniserver Targets (with immediate version check)
        Write-Log -Message "($FunctionName) [MSPreCheck_DEBUG_ENTRY] Entering Miniserver Targets section." -Level DEBUG
        Write-Log -Message "($FunctionName) [MS PreCheck] Initializing and checking Miniserver targets..." -Level INFO
        if (Test-Path $WorkflowContext.MSListPath) {
            try { # Inner try for reading MS list and processing each MS
                $MSEntriesPreCheck = Get-Content $WorkflowContext.MSListPath -ErrorAction Stop | Where-Object { $_ -match '\S' -and $_.TrimStart()[0] -ne '#' }
                foreach ($msEntryPreCheck in $MSEntriesPreCheck) {
                    $msIPForName = ($msEntryPreCheck -split '@')[-1] -split ':' | Select-Object -First 1
                    Write-Log -Level DEBUG -Message ("($FunctionName) [MS PreCheck] Processing MS Entry: {0}" -f ($msEntryPreCheck -replace "([Pp]assword=)[^;]+", '$1********'))
                    
                    # Skip certificate check by default unless EnforceSSLCertificate is specified
                    $skipCert = -not $WorkflowContext.Params.EnforceSSLCertificate
                    $msVersionInfo = Get-MiniserverVersion -MSEntry $msEntryPreCheck -SkipCertificateCheck:$skipCert -TimeoutSec 10 -ErrorAction SilentlyContinue
                    
                    # Log the error but do NOT fall back to HTTP for security reasons
                    if ($msVersionInfo.Error -and $msEntryPreCheck -match '^https://') {
                        Write-Log -Level WARN -Message "($FunctionName) [MS PreCheck] HTTPS connection failed for '$msIPForName': $($msVersionInfo.Error)"
                        Write-Log -Level INFO -Message "($FunctionName) [MS PreCheck] NOT falling back to HTTP for security reasons. Please check the Miniserver HTTPS configuration or use HTTP in UpdateLoxoneMSList.txt"
                    }
                    
                    $currentMSVersion = "Unknown"
                    $msStatus = "PendingCheck"
                    $msUpdateNeeded = $false

                    if ($msVersionInfo.Error) {
                        Write-Log -Message "($FunctionName) [MS PreCheck] Error getting version for '$msIPForName': $($msVersionInfo.Error)" -Level WARN
                        $currentMSVersion = "ErrorConnecting"
                        $msStatus = "ErrorConnecting"
                        if ($Prerequisites.LatestConfigVersionNormalized) {
                            $msUpdateNeeded = $true
                        } else {
                            $msStatus = "ErrorConnecting_NoTargetVersion"
                            $msUpdateNeeded = $false
                        }
                    } else {
                        $currentMSVersion = $msVersionInfo.Version
                        if (-not [string]::IsNullOrWhiteSpace($currentMSVersion) -and $currentMSVersion -ne "Unknown") {
                            # Log connection encryption details
                            $connectionType = if ($msEntryPreCheck -match '^https://') { 'HTTPS (Encrypted)' } else { 'HTTP (Plain text)' }
                            Write-Log -Message "($FunctionName) [MS PreCheck] Connection details for '$msIPForName': Protocol=$connectionType, SkipCertCheck=$skipCert" -Level INFO
                            
                            $normalizedCurrentMSVersion = Convert-VersionString $currentMSVersion
                            Write-Log -Message "($FunctionName) [MS PreCheck] MS '$msIPForName' current version: $currentMSVersion (Normalized: $normalizedCurrentMSVersion)" -Level INFO

                            if ($Prerequisites.LatestConfigVersionNormalized) {
                                if ($normalizedCurrentMSVersion -ne $Prerequisites.LatestConfigVersionNormalized) {
                                    if ([System.Version]$normalizedCurrentMSVersion -lt [System.Version]$Prerequisites.LatestConfigVersionNormalized) {
                                        Write-Log -Message "($FunctionName) [MS PreCheck] MS '$msIPForName' version '$normalizedCurrentMSVersion' is older than target '$($Prerequisites.LatestConfigVersionNormalized)'. Update needed." -Level INFO
                                        $msUpdateNeeded = $true
                                        $msStatus = "NeedsUpdate"
                                    } else {
                                        Write-Log -Message "($FunctionName) [MS PreCheck] MS '$msIPForName' version '$normalizedCurrentMSVersion' is newer than target '$($Prerequisites.LatestConfigVersionNormalized)'. No update." -Level INFO
                                        $msUpdateNeeded = $false
                                        $msStatus = "NewerThanTarget"
                                    }
                                } else {
                                    Write-Log -Message "($FunctionName) [MS PreCheck] MS '$msIPForName' is already at target version '$($Prerequisites.LatestConfigVersionNormalized)'." -Level INFO
                                    $msUpdateNeeded = $false
                                    $msStatus = "UpToDate"
                                }
                            } else {
                                Write-Log -Message "($FunctionName) [MS PreCheck] Target MS version not available. Cannot determine if update is needed for '$msIPForName'." -Level WARN
                                $msStatus = "NoTargetVersion"
                                $msUpdateNeeded = $false
                            }
                        } else {
                             Write-Log -Message "($FunctionName) [MS PreCheck] Get-MiniserverVersion returned an empty or 'Unknown' version for '$msIPForName'. Treating as error." -Level WARN
                             $currentMSVersion = "ErrorReadingVersion"
                             $msStatus = "ErrorReadingVersion"
                             if ($Prerequisites.LatestConfigVersionNormalized) {
                                $msUpdateNeeded = $true
                             } else {
                                $msStatus = "ErrorReadingVersion_NoTargetVersion"
                                $msStatus = "ErrorReadingVersion_NoTargetVersion"
                                $msUpdateNeeded = $false
                            }
                       }
                   }
                   Write-Log -Message "($FunctionName) [MS PreCheck] Passed all version checks for MS '$msIPForName'. Status: '$msStatus', UpdateNeeded: '$msUpdateNeeded'. Proceeding to create/add entry." -Level DEBUG

                   $msTargetEntry = $null # Initialize to null
                   try {
                       Write-Log -Message "($FunctionName) [MS PreCheck] Attempting to create PSCustomObject for MS '$msIPForName'." -Level DEBUG
                       $msTargetEntry = [PSCustomObject]@{
                           Name                = "MS $msIPForName"
                           Type                = "Miniserver"
                           InitialVersion      = $currentMSVersion
                           TargetVersion       = $Prerequisites.LatestConfigVersionNormalized
                           UpdateNeeded        = $msUpdateNeeded
                           Status              = $msStatus
                           UpdatePerformed     = $false
                           VersionAfterUpdate  = $null
                           OriginalEntry       = $msEntryPreCheck
                           Channel             = $WorkflowContext.Params.Channel
                           Error               = $null
                       }
                       Write-Log -Message "($FunctionName) [MS PreCheck] Successfully created PSCustomObject for MS '$($msTargetEntry.Name)'." -Level DEBUG
                   } catch {
                       Write-Log -Message "($FunctionName) [MS PreCheck] CRITICAL ERROR creating PSCustomObject for MS '$msIPForName'. Error: $($_.Exception.Message)" -Level ERROR
                       # Optionally continue to next MS or rethrow, for now, just log and it won't be added
                       continue
                   }

                   if ($msTargetEntry) {
                       Write-Log -Message "($FunctionName) [UpdateTargets] Attempting to add MS '$($msTargetEntry.Name)' to UpdateTargetsInfo. Current count: $($pipelineData.UpdateTargetsInfo.Count)" -Level DEBUG
                       $addResult = $pipelineData.UpdateTargetsInfo.Add($msTargetEntry)
                       Write-Log -Message "($FunctionName) [UpdateTargets] Add operation result (usually index): '$addResult'. New count: $($pipelineData.UpdateTargetsInfo.Count)" -Level DEBUG
                       Write-Log -Message "($FunctionName) [UpdateTargets] Added MS '$($msTargetEntry.Name)': Initial='$($msTargetEntry.InitialVersion)', Target='$($msTargetEntry.TargetVersion)', UpdateNeeded='$($msTargetEntry.UpdateNeeded)', Status='$($msTargetEntry.Status)'" -Level DEBUG
                   } else {
                       Write-Log -Message "($FunctionName) [MS PreCheck] msTargetEntry was null for '$msIPForName', skipping Add to UpdateTargetsInfo." -Level WARN
                   }
               } # End foreach $msEntryPreCheck
           } catch { # Catch for reading MS list and processing each MS
            }
        } else {
            Write-Log -Message "($FunctionName) [UpdateTargets] MS list '$($WorkflowContext.MSListPath)' not found. No Miniserver targets added." -Level INFO
        }

        # --- Calculate Progress Weights and Steps ---
        $ProgressStepsDefinition = @(
            @{ ID = 'InitialCheck';   Description = 'Checking versions';              Weight = 1; Condition = { $true } };
            @{ ID = 'DownloadConfig'; Description = 'Downloading Loxone Config';      Weight = 2; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'ExtractConfig';  Description = 'Extracting Loxone Config';       Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'InstallConfig';  Description = 'Installing Loxone Config';       Weight = 3; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'VerifyConfig';   Description = 'Verifying Loxone Config install';Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded -and $_.Status -ne "UpdateSkipped (ProcessRunningAtInstall)"}).Count -gt 0 } };
            @{ ID = 'DownloadApp';    Description = 'Downloading Loxone App';         Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'InstallApp';     Description = 'Installing Loxone App';          Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'VerifyApp';      Description = 'Verifying Loxone App install';   Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded -and $_.Status -ne "UpdateSkipped (ProcessRunningAtInstall)"}).Count -gt 0 }};
            @{ ID = 'CheckMSVersions';Description = 'Confirming Miniserver Versions'; Weight = 1; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver"}).Count -gt 0 } };
            @{ ID = 'UpdateMS';       Description = 'Updating Miniservers';           Weight = 0; Condition = { ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count -gt 0 } };
            @{ ID = 'Finalize';       Description = 'Finalizing';                     Weight = 1; Condition = { $true } }
        )

        $script:WorkflowStepDefinitions = $ProgressStepsDefinition
        Write-Log -Message "($FunctionName) Stored ProgressStepsDefinition in script:WorkflowStepDefinitions." -Level DEBUG

        $LocalTotalWeight = 0
Write-Log -Message "($FunctionName) Start Calculating TotalWeight" -Level DEBUG
        foreach ($stepDef in $ProgressStepsDefinition) {
            $runStep = $false
            try {
                $runStep = Invoke-Command -ScriptBlock $stepDef.Condition
                Write-Log -Message "($FunctionName) WeightCalc: StepDef '$($stepDef.ID)' Condition evaluated to: $runStep" -Level DEBUG
            } catch {
                Write-Log -Message "($FunctionName) Error evaluating condition for weight calc step '$($stepDef.ID)': $($_.Exception.Message)" -Level WARN
            }
            if ($runStep) {
                if ($stepDef.ID -eq 'UpdateMS') {
                    $msToUpdateCount = ($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count
                    $msWeightPerServer = 2
                    $LocalTotalWeight += ($msToUpdateCount * $msWeightPerServer)
Write-Log -Message "($FunctionName) WeightCalc: StepDef '$($stepDef.ID)' (UpdateMS) - MS to update: $msToUpdateCount, Weight per MS: $msWeightPerServer, Added weight: $($msToUpdateCount * $msWeightPerServer). Current LocalTotalWeight: $LocalTotalWeight" -Level DEBUG
                } else {
                    $LocalTotalWeight += $stepDef.Weight
Write-Log -Message "($FunctionName) WeightCalc: StepDef '$($stepDef.ID)' - Added weight: $($stepDef.Weight). Current LocalTotalWeight: $LocalTotalWeight" -Level DEBUG
                }
            }
else {
                Write-Log -Message "($FunctionName) WeightCalc: StepDef '$($stepDef.ID)' - Condition false, no weight added." -Level DEBUG
            }
        }
        $pipelineData.TotalWeight = $LocalTotalWeight
Write-Log -Message "($FunctionName) End Calculating TotalWeight." -Level INFO
        Write-Log -Message "($FunctionName) Total calculated progress weight: $($pipelineData.TotalWeight)" -Level INFO

Write-Log -Message "($FunctionName) Start Calculating TotalSteps for UI" -Level DEBUG
Write-Log -Message "($FunctionName) TotalStepsUI: Initial base = $LocalTotalSteps" -Level DEBUG
        $LocalTotalSteps = 1
        $LocalTotalDownloads = 0
        if (($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Config" -and $_.UpdateNeeded}).Count -gt 0) { $LocalTotalSteps += 3; $LocalTotalDownloads += 1 }
Write-Log -Message "($FunctionName) TotalStepsUI: Config update needed. Added 3 steps, 1 download. Current LocalTotalSteps: $LocalTotalSteps, LocalTotalDownloads: $LocalTotalDownloads" -Level DEBUG
        if (($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "App" -and $_.UpdateNeeded}).Count -gt 0)    { $LocalTotalSteps += 2; $LocalTotalDownloads += 1 }
Write-Log -Message "($FunctionName) TotalStepsUI: App update needed. Added 2 steps, 1 download. Current LocalTotalSteps: $LocalTotalSteps, LocalTotalDownloads: $LocalTotalDownloads" -Level DEBUG
        if (($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver"}).Count -gt 0) { $LocalTotalSteps += 1 }
Write-Log -Message "($FunctionName) TotalStepsUI: Miniservers defined. Added 1 step (for MS Check). Current LocalTotalSteps: $LocalTotalSteps" -Level DEBUG
        if (($pipelineData.UpdateTargetsInfo | Where-Object {$_.Type -eq "Miniserver" -and $_.UpdateNeeded}).Count -gt 0) { $LocalTotalSteps += 1 }
Write-Log -Message "($FunctionName) TotalStepsUI: Miniservers need update. Added 1 step (for MS Update bulk). Current LocalTotalSteps: $LocalTotalSteps" -Level DEBUG
        # Note: The MS Update function increments currentStep internally, so we don't add an extra step here
        $LocalTotalSteps += 1
Write-Log -Message "($FunctionName) TotalStepsUI: Added 1 step for Finalizing. Current LocalTotalSteps: $LocalTotalSteps" -Level DEBUG

        $pipelineData.TotalSteps = $LocalTotalSteps
        $pipelineData.TotalDownloads = $LocalTotalDownloads
Write-Log -Level INFO -Message "($FunctionName) End Calculating TotalSteps for UI. Recalculated Totals - Steps: $($pipelineData.TotalSteps), Downloads: $($pipelineData.TotalDownloads)"
        Write-Log -Level INFO -Message "($FunctionName) Recalculated Totals for UI - Steps: $($pipelineData.TotalSteps), Downloads: $($pipelineData.TotalDownloads)"

        $InitialCheckStep = $ProgressStepsDefinition | Where-Object {$_.ID -eq 'InitialCheck'} | Select-Object -First 1
        if ($InitialCheckStep) {
            $pipelineData.InitialCheckWeight = $InitialCheckStep.Weight
        } else {
            $pipelineData.InitialCheckWeight = 1
            Write-Log -Message "($FunctionName) WARN: Could not find 'InitialCheck' step. Defaulting to 1." -Level WARN
        }
        Write-Log -Message "($FunctionName) InitialCheckWeight determined: $($pipelineData.InitialCheckWeight)" -Level DEBUG
        Write-Log -Message "($FunctionName) [EndOfTryBlock_DEBUG] Reached end of main try block in Initialize-UpdatePipelineData." -Level DEBUG
    } catch { # Catch for the main function try
        $pipelineData.Succeeded = $false
        $pipelineData.Reason = "PipelineDataInitException"
        $pipelineData.Error = $_
        Write-Log -Message "($FunctionName) Exception during pipeline data initialization: $($_.Exception.Message). Full Error: ($($_ | Out-String))" -Level ERROR
    }

    Write-Log -Message "($FunctionName) Finished initializing update pipeline data." -Level INFO
    return $pipelineData
}
function Test-PipelineStepShouldRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.ArrayList]$TargetsInfo,

        [Parameter(Mandatory=$true)]
        [string]$ExpectedType,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ScriptBlock]$ConditionBlock
    )

    foreach ($item in $TargetsInfo) {
        if ($item.Type -eq $ExpectedType) {
            # Invoke the custom condition scriptblock, passing the current item
            if (Invoke-Command -ScriptBlock $ConditionBlock -ArgumentList $item) {
                return $true # Condition met for at least one item of the expected type
            }
        }
    }
    return $false # No item of the expected type met the condition
}
Export-ModuleMember -Function Initialize-ScriptWorkflow, Get-LoxoneUpdatePrerequisites, Invoke-DownloadLoxoneConfig, Invoke-ExtractLoxoneConfig, Invoke-InstallLoxoneConfig, Invoke-DownloadLoxoneApp, Invoke-InstallLoxoneApp, Invoke-CheckMiniserverVersions, Invoke-UpdateMiniserversInBulk, Initialize-UpdatePipelineData, Get-StepWeight, Test-PipelineStepShouldRun
