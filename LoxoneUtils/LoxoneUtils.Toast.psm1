# Optimized LoxoneUtils.Toast Module
# Key improvements:
# 1. Reduced redundant logging
# 2. Centralized parameter validation
# 3. Simplified data binding updates
# 4. Better separation of concerns
# 5. Removed duplicate code blocks

#region Module Initialization

# Import safe wrapper functions
. "$PSScriptRoot\LoxoneUtils.Toast.SafeWrappers.ps1"

# Thread safety: Create mutex for toast operations
$script:ToastMutex = [System.Threading.Mutex]::new($false, "Global\LoxoneToast_$([System.Diagnostics.Process]::GetCurrentProcess().Id)")

# Check if toast initialization is suppressed
$script:SuppressToastInit = $Global:SuppressLoxoneToastInit -eq $true
if ($script:SuppressToastInit) {
    Write-Verbose "Toast module initialization suppressed by Global:SuppressLoxoneToastInit"
    # Don't return - we still need to export functions
}

$script:IsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem

if (-not $script:SuppressToastInit -and -not $script:IsSystem -and -not (Get-Module -Name BurntToast -ListAvailable)) {
    Write-Warning "BurntToast module not installed. Toast notifications unavailable."
    Write-Warning "Install with: Install-Module -Name BurntToast -Force"
}
#endregion

#region Toast Configuration
class ToastConfiguration {
    [string]$DefaultId = "LoxoneUpdateStatusToast"
    [string]$AppIdFormat = '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
    [hashtable]$DataTemplate = @{
        StatusText            = "Initializing..."
        ProgressBarStatus     = "Download: -"
        ProgressBarValue      = 0.0
        OverallProgressStatus = "Overall: 0%"
        OverallProgressValue  = 0.0
        StepNumber            = 0
        TotalSteps            = 1
        StepName              = "Initializing..."
        DownloadFileName      = ""
        DownloadNumber        = 0
        TotalDownloads        = 0
        CurrentWeight         = 0
        TotalWeight           = 1
        DownloadSpeedLine     = ""
        DownloadTimeLine      = ""
        DownloadSizeLine      = ""
        # Parallel mode progress bars
        ConfigStatus          = "Waiting..."
        ConfigProgress        = 0.0
        AppStatus             = "Waiting..."
        AppProgress           = 0.0
        MiniserverStatus      = "Waiting..."
        MiniserverProgress    = 0.0
        MiniserversTitle      = "Miniservers"
    }
}

# Initialize global state only if not suppressed OR in test mode
if (-not $script:SuppressToastInit) {
    $script:Config = [ToastConfiguration]::new()
    if (-not (Test-Path variable:Global:PersistentToastId)) {
        $Global:PersistentToastId = $script:Config.DefaultId
    }
    if (-not (Test-Path variable:Global:PersistentToastInitialized)) {
        $Global:PersistentToastInitialized = $false
    }
    # Initialize script start time for runtime tracking
    if (-not (Test-Path variable:Global:ScriptStartTime)) {
        $Global:ScriptStartTime = Get-Date
    }
} else {
    # Create minimal config for suppressed mode
    $script:Config = [ToastConfiguration]::new()
}
# CRITICAL FIX: Only initialize data binding ONCE per session
# This prevents the toast from dismissing when transitioning between operations
if (-not $script:SuppressToastInit) {
    $mutexAcquired = $false
    try {
        # Thread-safe initialization check
        $mutexAcquired = $script:ToastMutex.WaitOne(1000)
        
        if (-not (Test-Path variable:Global:PersistentToastData)) {
            # Only log if logging infrastructure is ready (prevents errors during module import)
            if ((Get-Command Write-SafeLog -ErrorAction SilentlyContinue) -and $Global:LogFile) {
                Write-SafeLog -Level Debug -Message "Initializing Global:PersistentToastData for the first time"
            }
            $Global:PersistentToastData = [ordered]@{
            StatusText            = "Initializing..."
            ProgressBarStatus     = "Download: -"
            ProgressBarValue      = 0.0
            OverallProgressStatus = "Overall: 0%"
            OverallProgressValue  = 0.0
            StepNumber            = 0
            TotalSteps            = 1
            StepName              = "Initializing..."
            DownloadFileName      = ""
            DownloadNumber        = 0
            TotalDownloads        = 0
            CurrentWeight         = 0
            TotalWeight           = 1
            DownloadSpeedLine     = ""
            DownloadTimeLine      = ""
            ConfigTitle           = "Loxone Config"
            AppTitle              = "Loxone App"
            DownloadSizeLine      = ""
            # Component-specific progress (Parallel mode)
            ConfigStatus          = "Waiting..."
            ConfigProgress        = 0.0
            ConfigDuration        = $null  # Clear any previous duration
            ConfigSymbol          = $null  # Clear any previous symbol
            AppStatus             = "Waiting..."
            AppProgress           = 0.0
            AppDuration           = $null  # Clear any previous duration
            AppSymbol             = $null  # Clear any previous symbol
            MiniserverStatus      = "Waiting..."
            MiniserverProgress    = 0.0
            MiniserverDuration    = $null  # Clear any previous duration
            MiniserverSymbol      = $null  # Clear any previous symbol
            MiniserversTitle      = "Miniservers"
        }
        } else {
            if (Get-Command Write-SafeLog -ErrorAction SilentlyContinue) {
                Write-SafeLog -Level Debug -Message "Global:PersistentToastData already exists - preserving existing object"
            }
        }
    } finally {
        if ($mutexAcquired) {
            try { $script:ToastMutex.ReleaseMutex() } catch {}
        }
    }
}
#endregion

#region Helper Functions
function Get-ParameterSummary {
    param([hashtable]$BoundParameters)
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        $summary = @{}
    foreach ($key in $BoundParameters.Keys) {
        $value = $BoundParameters[$key]
        $summary[$key] = if ($value -is [string] -and $value.Length -gt 50) {
            "$($value.Substring(0, 47))..."
        } else { $value }
    }
        return $summary
    }
    finally {
        Exit-SafeFunction
    }
}
#endregion

#region AppId Management
function Get-LoxoneToastAppId {
    [CmdletBinding()]
    param([string]$PreFoundPath)
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $loxonePath = $PreFoundPath
        if (-not $loxonePath) {
            Write-SafeLog -Level Debug -Message "No pre-found path provided. Searching registry..."
            try {
                $loxonePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
            } catch {
                Write-SafeLog -Level Warn -Message "Error calling Get-LoxoneExePath: $($_.Exception.Message)"
            }
        }
        
        if ($loxonePath) {
            Write-SafeLog -Level Debug -Message "Using hardcoded Loxone Config AppId"
            return '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
        }
        
        Write-SafeLog -Level Debug -Message "No Loxone Config found. Using default AppId."
        return $null
    }
    finally { Exit-SafeFunction }
}

function Initialize-LoxoneToastAppId {
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Initialize-LoxoneToastAppId: Suppressed by SuppressToastInit"
        return
    }
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $script:ResolvedToastAppId = Get-LoxoneToastAppId -PreFoundPath $script:InstalledExePath
        Write-SafeLog -Level Debug -Message "Resolved Toast AppId: '$($script:ResolvedToastAppId | Out-String)'"
    }
    finally { Exit-SafeFunction }
}
#endregion

#region Data Binding Updates
function Update-ToastDataBinding {
    <#
    .SYNOPSIS
    Safely updates the global toast data binding without recreating the object
    .DESCRIPTION
    CRITICAL: This function only updates individual keys to preserve the data binding.
    Never assign a new hashtable to $Global:PersistentToastData!
    Thread-safe: Uses mutex to prevent concurrent modifications.
    #>
    param(
        [hashtable]$Updates,
        [switch]$PreserveExisting
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    $mutexAcquired = $false
    try {
        # Acquire mutex for thread-safe access
        try {
            $mutexAcquired = $script:ToastMutex.WaitOne(5000) # 5 second timeout
            if (-not $mutexAcquired) {
                Write-SafeLog -Level Warn -Message "Could not acquire toast mutex within timeout"
            }
        } catch {
            Write-SafeLog -Level Warn -Message "Error acquiring toast mutex: $_"
        }
        
        if (-not $Updates) { return }
    
        # Verify we're not accidentally trying to replace the entire object
        if ($Updates -eq $Global:PersistentToastData) {
            Write-SafeLog -Level Error -Message "CRITICAL: Attempted to replace entire PersistentToastData object!"
            throw "Cannot replace PersistentToastData object - use individual key updates only"
        }
        
        foreach ($key in $Updates.Keys) {
            if ($Updates[$key] -ne $null -or -not $PreserveExisting) {
                # CRITICAL: Update individual key, never recreate the hashtable
                $Global:PersistentToastData[$key] = $Updates[$key]
            }
        }
    }
    finally {
        if ($mutexAcquired) {
            try {
                $script:ToastMutex.ReleaseMutex()
            } catch {
                Write-SafeLog -Level Warn -Message "Error releasing toast mutex: $_"
            }
        }
        Exit-SafeFunction
    }
}

function Build-StatusText {
    param(
        [hashtable]$Params
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Download details are now shown in progress bar text, not in main status text
        # This keeps the main text area clean and focused on high-level status
        
        # When no details available, show enhanced context-based messages
        if ($Params.StepNumber -and $Params.TotalSteps -and $Params.StepName) {
            # Check if this is the final step
            if ($Params.StepNumber -eq $Params.TotalSteps) {
                # Get success/error status from parameters
                $success = -not ($Params.ContainsKey('ErrorOccurred') -and $Params.ErrorOccurred)
                $statusSymbol = if ($success) { "?" } else { "?" }
                
                # Build runtime summary for completed steps only
                $runtimeSummary = Build-RuntimeSummary -CurrentStep $Params.StepNumber -StepName $Params.StepName
                
                # Check if any updates were actually performed
                $anyUpdates = $false
                if ((Test-Path variable:Global:StepRuntimes) -and $Global:StepRuntimes.Count -gt 0) {
                    # Check if we have meaningful runtime for update categories
                    foreach ($key in @('Conf', 'APP', 'MS')) {
                        if ($Global:StepRuntimes.ContainsKey($key) -and $Global:StepRuntimes[$key] -ge 0.1) {
                            $anyUpdates = $true
                            break
                        }
                    }
                }
                
                if (-not $anyUpdates) {
                    # No updates performed - just checked
                    return "$statusSymbol Process complete`nNo updates required"
                } elseif ($runtimeSummary) {
                    # Updates performed - show what was updated with runtime
                    return "$statusSymbol Process complete`n$runtimeSummary"
                } else {
                    # Updates performed but no runtime data
                    return "$statusSymbol Process complete"
                }
            }
            
            # Enhanced step-specific messages
            $stepName = $Params.StepName.ToLower()
            
            if ($stepName -eq 'downloads complete') {
                return "? All downloads completed`nVerifying file integrity..."
            }
            elseif ($stepName -like '*initial*' -or $stepName -like '*check*') {
                return "?? Checking for available updates`nConnecting to update servers..."
            }
            elseif ($stepName -like '*download*') {
                return "?? Preparing file downloads`nValidating download sources..."
            }
            elseif ($stepName -like '*config*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "?? Installing $displayName`nUpdating system components..."
            }
            elseif ($stepName -like '*app*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "?? Installing $displayName`nConfiguring application settings..."
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*config*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "?? Extracting $displayName`nPreparing installation files..."
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*app*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "?? Extracting $displayName`nPreparing application files..."
            }
            elseif ($stepName -like '*miniserver*' -or $stepName -like '*ms*') {
                return "?? Updating Miniserver firmware`nEstablishing secure connection..."
            }
            elseif ($stepName -like '*finali*' -or $stepName -like '*complet*') {
                return "?? Finalizing installation`nCleaning up temporary files..."
            }
            else {
                return "? Processing workflow step`nPlease wait..."
            }
        }
        
        # Initial state: clear any previous run text
        return "?? Initializing update process`nPreparing system checks..."
    }
    finally {
        Exit-SafeFunction
    }
}

function Build-ProgressBarStatus {
    param(
        [hashtable]$Params
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Active download in progress
        if ($Params.DownloadFileName) {
            $downloadText = if ($Params.DownloadNumber -and $Params.TotalDownloads) {
                "Download $($Params.DownloadNumber)/$($Params.TotalDownloads): $($Params.DownloadFileName)"
            } else {
                "Download: $($Params.DownloadFileName)"
            }
            
            # Add download details to progress bar text
            $downloadDetails = @()
            if ($Params.DownloadSpeed) { $downloadDetails += $Params.DownloadSpeed }
            if ($Params.DownloadRemainingTime) { $downloadDetails += $Params.DownloadRemainingTime }
            if ($Params.DownloadSizeProgress) { $downloadDetails += $Params.DownloadSizeProgress }
            
            if ($downloadDetails.Count -gt 0) {
                return "$downloadText | $($downloadDetails -join ' | ')"
            }
            
            return $downloadText
        }
        
        # Downloads completed
        if ($Params.StepName -eq 'Downloads Complete') {
            return "Downloads: Completed"
        }
        
        # Step-based status when no active downloads (clears old download text)
        if ($Params.StepNumber -and $Params.TotalSteps -and $Params.StepName) {
            $stepName = $Params.StepName.ToLower()
            
            # Check if this is the final step
            if ($Params.StepNumber -eq $Params.TotalSteps) {
                return "Process: Completed"
            }
            
            if ($stepName -like '*initial*' -or $stepName -like '*check*') {
                return "Task: Checking for updates"
            }
            elseif ($stepName -like '*download*' -and $stepName -notlike '*complete*') {
                return "Task: Preparing downloads"
            }
            elseif ($stepName -like '*config*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "Task: Installing $displayName"
            }
            elseif ($stepName -like '*app*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "Task: Installing $displayName"
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*config*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "Task: Extracting $displayName"
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*app*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "Task: Extracting $displayName"
            }
            elseif ($stepName -like '*miniserver*' -or $stepName -like '*ms*') {
                return "Task: Updating Miniserver"
            }
            elseif ($stepName -like '*finali*' -or $stepName -like '*complet*') {
                return "Task: Finalizing"
            }
            else {
                return "Task: Processing"
            }
        }
        
        # Initial state: clear any previous download text
        return "Task: Initializing"
    }
    finally {
        Exit-SafeFunction
    }
}

function Build-OverallProgressStatus {
    param(
        [hashtable]$Params
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # New function: show step info in overall progress bar (reorganized from main text)
        if ($Params.StepNumber -and $Params.TotalSteps -and $Params.StepName) {
            return "Step $($Params.StepNumber)/$($Params.TotalSteps): $($Params.StepName)"
        }
        
        # Fallback: show percentage-based progress if no step info
        if ($Params.ContainsKey('CurrentWeight') -and $Params.ContainsKey('TotalWeight')) {
            $totalWeight = [Math]::Max(1, $Params.TotalWeight)
            $progress = [Math]::Max(0.0, [Math]::Min(1.0, ($Params.CurrentWeight / $totalWeight)))
            return "Overall: {0:P0}" -f $progress
        }
        
        # Final fallback: preserve existing text
        return $Global:PersistentToastData['OverallProgressStatus']
    }
    finally {
        Exit-SafeFunction
    }
}

function Reset-RuntimeTracking {
    # Reset all timing variables for a new process
    $Global:ScriptStartTime = Get-Date
    $Global:StepTimings = @{}
    $Global:StepRuntimes = @{}
    $Global:LastStepKey = $null
    Write-SafeLog -Level Debug -Message "Reset runtime tracking - new process started"
}

function Track-StepTiming {
    param(
        [string]$StepName,
        [int]$StepNumber
    )
    
    if (-not $StepName) { return }
    
    # Initialize timing tracking if not exists
    if (-not (Test-Path variable:Global:StepTimings)) {
        $Global:StepTimings = @{}
    }
    if (-not (Test-Path variable:Global:StepRuntimes)) {
        $Global:StepRuntimes = @{}
    }
    
    # Reset timing on first step of new process
    if ($StepNumber -eq 1 -or ($StepName -like '*initial*' -and $Global:StepTimings.Count -eq 0)) {
        Reset-RuntimeTracking
    }
    
    $stepKey = Get-StepKey -StepName $StepName
    if (-not $stepKey) { return }
    
    $now = Get-Date
    
    # Get previous category
    $previousStep = if ((Test-Path variable:Global:LastStepKey)) { $Global:LastStepKey } else { $null }
    
    # If switching to a new category, finalize the previous one
    if ($previousStep -and $previousStep -ne $stepKey -and $Global:StepTimings.ContainsKey($previousStep)) {
        $startTime = $Global:StepTimings[$previousStep]
        $runtime = ($now - $startTime).TotalMinutes
        
        if ($Global:StepRuntimes.ContainsKey($previousStep)) {
            $Global:StepRuntimes[$previousStep] += $runtime
        } else {
            $Global:StepRuntimes[$previousStep] = $runtime
        }
        
        Write-SafeLog -Level Debug -Message "Accumulated time for $previousStep`: $runtime min (total: $($Global:StepRuntimes[$previousStep]) min)"
    }
    
    # Track active category timing
    if (-not $Global:StepTimings.ContainsKey($stepKey)) {
        # First time seeing this category - start timing
        $Global:StepTimings[$stepKey] = $now
        Write-SafeLog -Level Debug -Message "Started timing for category: $stepKey ($StepName)"
    }
    elseif ($previousStep -eq $stepKey) {
        # Same category continuing
        Write-SafeLog -Level Debug -Message "Continuing category $stepKey with: $StepName"
    }
    else {
        # Returning to a category that was tracked before
        $Global:StepTimings[$stepKey] = $now
        Write-SafeLog -Level Debug -Message "Resumed timing for category: $stepKey ($StepName)"
    }
    
    # Remember the current category for next call
    $Global:LastStepKey = $stepKey
}

function Build-RuntimeSummary {
    param(
        [int]$CurrentStep,
        [string]$StepName
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Finalize timing for the last active category
        if ((Test-Path variable:Global:LastStepKey) -and $Global:LastStepKey -and 
            (Test-Path variable:Global:StepTimings) -and 
            $Global:StepTimings.ContainsKey($Global:LastStepKey)) {
            
            $lastKey = $Global:LastStepKey
            $startTime = $Global:StepTimings[$lastKey]
            $runtime = ((Get-Date) - $startTime).TotalMinutes
            
            if (-not (Test-Path variable:Global:StepRuntimes)) {
                $Global:StepRuntimes = @{}
            }
            
            if ($Global:StepRuntimes.ContainsKey($lastKey)) {
                $Global:StepRuntimes[$lastKey] += $runtime
            } else {
                $Global:StepRuntimes[$lastKey] = $runtime
            }
            
            Write-SafeLog -Level Debug -Message "Final accumulation for $lastKey`: $runtime min (total: $($Global:StepRuntimes[$lastKey]) min)"
        }
        
        # Calculate total runtime from script start (fallback if not set)
        $startTime = if ((Test-Path variable:Global:ScriptStartTime)) { 
            $Global:ScriptStartTime 
        } else { 
            # Fallback: use earliest step timing or current time minus 1 minute
            if ((Test-Path variable:Global:StepTimings) -and $Global:StepTimings.Count -gt 0) {
                ($Global:StepTimings.Values | Sort-Object)[0]
            } else {
                (Get-Date).AddMinutes(-1)
            }
        }
        
        $totalScriptTime = ((Get-Date) - $startTime).TotalMinutes
        # Ensure minimum of 0.1 minutes to avoid showing 0.0
        $totalScriptTime = [Math]::Max($totalScriptTime, 0.1)
        $totalScriptRounded = [Math]::Round($totalScriptTime, 1)
        
        # Build compact runtime summary for completed steps
        $completedSteps = @()
        $totalStepTime = 0.0
        
        if ((Test-Path variable:Global:StepRuntimes)) {
            # Use dynamic categories from StepCategories
            $categoryKeys = $script:StepCategories.Keys | Sort-Object { $script:StepCategories[$_].Priority }
            
            foreach ($key in $categoryKeys) {
                if ($Global:StepRuntimes.ContainsKey($key)) {
                    $time = [Math]::Round($Global:StepRuntimes[$key], 1)
                    # Skip categories with effectively zero runtime (less than 0.05 minutes = 3 seconds)
                    if ($time -lt 0.1) { continue }
                    
                    $displayName = $script:StepCategories[$key].DisplayName
                    $completedSteps += "$displayName`:$time"
                    $totalStepTime += $Global:StepRuntimes[$key]
                }
            }
        }
        
        # Always show total runtime, with step details if available
        if ($completedSteps.Count -gt 0) {
            return "$($completedSteps -join ' ') Total:$totalScriptRounded Min"
        } else {
            return "Total:$totalScriptRounded Min"
        }
    }
    finally {
        Exit-SafeFunction
    }
}

# Define step categorization rules dynamically
$script:StepCategories = @{
    'Conf' = @{
        DisplayName = 'Conf'
        Patterns = @(
            '*config*'  # Matches all Config operations: download, extract, verify, install
        )
        Priority = 1  # Higher priority for specific matches
    }
    'APP' = @{
        DisplayName = 'APP'
        Patterns = @(
            '*app*'  # Matches all App operations: download, extract, verify, install
        )
        Priority = 2
    }
    'MS' = @{
        DisplayName = 'MS'  
        Patterns = @(
            '*miniserver*'
            '*ms *'
            '* ms*'
            '*updating ms*'
            '*checking ms*'
        )
        Priority = 3
    }
}

function Get-StepKey {
    param([string]$StepName)
    
    if (-not $StepName) { return $null }
    
    $stepLower = $StepName.ToLower()
    
    # Check each category in priority order
    $sortedCategories = $script:StepCategories.GetEnumerator() | 
        Sort-Object { $_.Value.Priority }
    
    foreach ($category in $sortedCategories) {
        foreach ($pattern in $category.Value.Patterns) {
            if ($stepLower -like $pattern) {
                return $category.Key
            }
        }
    }
    
    return $null
}

function Calculate-ProgressValues {
    param(
        [hashtable]$Params
    )
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        $result = @{}
    
    # Download progress
    if ($Params.ContainsKey('ProgressPercentage')) {
        $result.ProgressBarValue = [Math]::Max(0.0, [Math]::Min(1.0, ($Params.ProgressPercentage / 100)))
    }
    
    # Overall progress
    if ($Params.ContainsKey('CurrentWeight') -and $Params.ContainsKey('TotalWeight')) {
        $totalWeight = [Math]::Max(1, $Params.TotalWeight)
        $progress = [Math]::Max(0.0, [Math]::Min(1.0, ($Params.CurrentWeight / $totalWeight)))
        $result.OverallProgressValue = $progress
        # Use new function for overall progress status (step info instead of percentage)
        $result.OverallProgressStatus = Build-OverallProgressStatus $Params
        $result.CurrentWeight = $Params.CurrentWeight
        $result.TotalWeight = $totalWeight
    }
    
        return $result
    }
    finally {
        Exit-SafeFunction
    }
}
#endregion

#region Main Toast Functions
function Update-PersistentToast {
    [CmdletBinding()]
    param(
        # Step Info
        [int]$StepNumber,
        [int]$TotalSteps,
        [string]$StepName,
        # Download Info
        [string]$DownloadFileName,
        [int]$DownloadNumber,
        [int]$TotalDownloads,
        [double]$ProgressPercentage,
        [string]$DownloadSpeed,
        [string]$DownloadRemainingTime,
        [string]$DownloadSizeProgress,
        # Weight Info
        [double]$CurrentWeight,
        [double]$TotalWeight,
        # Component-specific progress (Parallel mode)
        [string]$ConfigStatus,
        [double]$ConfigProgress,
        [string]$ConfigTitle,
        [string]$AppStatus,
        [double]$AppProgress,
        [string]$AppTitle,
        [string]$MiniserverStatus,
        [double]$MiniserverProgress,
        [string]$MiniserversTitle,
        # Context (Required)
        [Parameter(Mandatory)][bool]$IsInteractive,
        [Parameter(Mandatory)][bool]$ErrorOccurred,
        [bool]$AnyUpdatePerformed = $false,
        [bool]$CallingScriptIsInteractive = $false,
        [string]$ActivityName,  # Add ActivityName parameter for component detection
        [bool]$CallingScriptIsSelfInvoked = $false
    )
    
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Update-PersistentToast: Suppressed by SuppressToastInit"
        return
    }
    
    # In parallel mode worker threads, we can't update toast directly (RPC_E_WRONG_THREAD)
    # Send the update through the queue instead
    if ($env:LOXONE_PARALLEL_MODE -eq "1" -and $env:LOXONE_PARALLEL_WORKER -eq "1") {
        Write-SafeLog -Level Debug -Message "Worker thread - sending toast update through queue"
        
        # Check if we have access to the progress queue
        if ($Global:WorkerProgressQueue) {
            # Build progress update message from parameters
            # Determine component from activity name or filename
            $component = 'Unknown'
            # Check ActivityName first (e.g., "Downloading Config", "Downloading App")
            if ($ActivityName) {
                if ($ActivityName -match 'Config') { 
                    $component = 'Config' 
                } elseif ($ActivityName -match 'App') { 
                    $component = 'App' 
                }
            }
            # Fall back to DownloadFileName if component still unknown
            if ($component -eq 'Unknown' -and $DownloadFileName) {
                if ($DownloadFileName -match 'Config') { 
                    $component = 'Config' 
                } elseif ($DownloadFileName -match 'App|160120250812|LoxoneApp') { 
                    $component = 'App' 
                }
            }
            
            Write-SafeLog -Level Debug -Message "Component detection: ActivityName='$ActivityName', DownloadFileName='$DownloadFileName', Detected='$component'"
            
            $progressMsg = @{
                Type = 'Download'
                Component = $component
                Progress = if ($PSBoundParameters.ContainsKey('ProgressPercentage')) { [int]$ProgressPercentage } else { 0 }
                Message = if ($PSBoundParameters.ContainsKey('StepName')) { $StepName } 
                         elseif ($PSBoundParameters.ContainsKey('DownloadSpeed')) { "Downloading..." }
                         else { "Processing..." }
                State = 'Downloading'
            }
            
            # Add step numbering if available
            if ($PSBoundParameters.ContainsKey('StepNumber')) { $progressMsg.StepNumber = $StepNumber }
            if ($PSBoundParameters.ContainsKey('TotalSteps')) { $progressMsg.TotalSteps = $TotalSteps }
            
            # Add download details if available
            if ($PSBoundParameters.ContainsKey('DownloadSpeed')) { $progressMsg.Speed = $DownloadSpeed }
            if ($PSBoundParameters.ContainsKey('DownloadSizeProgress')) { $progressMsg.SizeProgress = $DownloadSizeProgress }
            if ($PSBoundParameters.ContainsKey('DownloadRemainingTime')) { $progressMsg.RemainingTime = $DownloadRemainingTime }
            
            try {
                $Global:WorkerProgressQueue.Enqueue($progressMsg)
                Write-SafeLog -Level Info -Message "Enqueued progress update: Component=$($progressMsg.Component), Type=$($progressMsg.Type), Progress=$($progressMsg.Progress), State=$($progressMsg.State), Message=$($progressMsg.Message)"
            } catch {
                Write-SafeLog -Level Warn -Message "Failed to enqueue progress update: $_"
            }
        }
        return
    }
    
    Start-Sleep -Milliseconds 50  # Small delay for visibility
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Verify data binding object still exists (safety check)
        if (-not (Test-Path variable:Global:PersistentToastData)) {
            Write-SafeLog -Level Error -Message "CRITICAL: Global:PersistentToastData was deleted! This should never happen."
            throw "PersistentToastData was deleted - toast binding is broken"
        }
        
        # Log parameter summary (consolidated)
        $paramSummary = Get-ParameterSummary $PSBoundParameters
        Write-SafeLog -Level Debug -Message "Update-PersistentToast called with $($PSBoundParameters.Count) parameters: $($paramSummary | ConvertTo-Json -Compress)"
        
        # Track step timing for runtime summary
        Track-StepTiming -StepName $StepName -StepNumber $StepNumber
        
        # Build updates from parameters
        $updates = @{}
        
        # Basic step info
        if ($PSBoundParameters.ContainsKey('StepNumber')) { $updates.StepNumber = $StepNumber }
        if ($PSBoundParameters.ContainsKey('TotalSteps')) { $updates.TotalSteps = $TotalSteps }
        if ($PSBoundParameters.ContainsKey('StepName')) { $updates.StepName = $StepName }
        
        # Download info
        if ($PSBoundParameters.ContainsKey('DownloadFileName')) { $updates.DownloadFileName = $DownloadFileName }
        if ($PSBoundParameters.ContainsKey('DownloadNumber')) { $updates.DownloadNumber = $DownloadNumber }
        if ($PSBoundParameters.ContainsKey('TotalDownloads')) { $updates.TotalDownloads = $TotalDownloads }
        
        # Download speed/time/size info
        if ($PSBoundParameters.ContainsKey('DownloadSpeed') -and $DownloadSpeed) { 
            $updates.DownloadSpeedLine = "Speed: $DownloadSpeed" 
        }
        if ($PSBoundParameters.ContainsKey('DownloadRemainingTime') -and $DownloadRemainingTime) { 
            $updates.DownloadTimeLine = "Time Rem: $DownloadRemainingTime" 
        }
        if ($PSBoundParameters.ContainsKey('DownloadSizeProgress') -and $DownloadSizeProgress) { 
            $updates.DownloadSizeLine = "Size: $DownloadSizeProgress" 
        }
        
        # Calculate derived values
        $updates.StatusText = Build-StatusText $PSBoundParameters
        $updates.ProgressBarStatus = Build-ProgressBarStatus $PSBoundParameters
        
        $progressValues = Calculate-ProgressValues $PSBoundParameters
        foreach ($key in $progressValues.Keys) {
            $updates[$key] = $progressValues[$key]
        }
        
        # Special case for completed downloads
        if ($StepName -eq 'Downloads Complete') {
            $updates.ProgressBarValue = 1.0
        }
        
        # Component-specific progress updates (Parallel mode)
        # IMPORTANT: Only update component progress if explicitly passed to avoid resetting them
        if ($env:LOXONE_PARALLEL_MODE -eq "1") {
            # In parallel mode, only update component values if they were explicitly passed
            if ($PSBoundParameters.ContainsKey('ConfigStatus')) { $updates.ConfigStatus = $ConfigStatus }
            if ($PSBoundParameters.ContainsKey('ConfigProgress')) { $updates.ConfigProgress = $ConfigProgress }
            if ($PSBoundParameters.ContainsKey('ConfigTitle')) { $updates.ConfigTitle = $ConfigTitle }
            if ($PSBoundParameters.ContainsKey('AppStatus')) { $updates.AppStatus = $AppStatus }
            if ($PSBoundParameters.ContainsKey('AppProgress')) { $updates.AppProgress = $AppProgress }
            if ($PSBoundParameters.ContainsKey('AppTitle')) { $updates.AppTitle = $AppTitle }
            if ($PSBoundParameters.ContainsKey('MiniserverStatus')) { $updates.MiniserverStatus = $MiniserverStatus }
            if ($PSBoundParameters.ContainsKey('MiniserverProgress')) { $updates.MiniserverProgress = $MiniserverProgress }
            if ($PSBoundParameters.ContainsKey('MiniserversTitle')) { $updates.MiniserversTitle = $MiniserversTitle }
            
            # If this is called from main script without component params, skip StatusText and progress bar updates
            # to avoid interfering with component progress bars
            if (-not ($PSBoundParameters.ContainsKey('ConfigStatus') -or 
                     $PSBoundParameters.ContainsKey('AppStatus') -or 
                     $PSBoundParameters.ContainsKey('MiniserverStatus'))) {
                Write-SafeLog -Level Debug -Message "Parallel mode: Main script call detected - preserving component progress bars"
                
                # Remove all updates that could interfere with component progress
                $keysToRemove = @('StatusText', 'ProgressBarStatus', 'ProgressBarValue', 
                                  'OverallProgressValue', 'OverallProgressStatus',
                                  'ConfigStatus', 'ConfigProgress', 'ConfigTitle',
                                  'AppStatus', 'AppProgress', 'AppTitle',
                                  'MiniserverStatus', 'MiniserverProgress', 'MiniserversTitle')
                
                foreach ($key in $keysToRemove) {
                    if ($updates.ContainsKey($key)) {
                        Write-SafeLog -Level Debug -Message "Removing $key from updates to preserve component state"
                        $updates.Remove($key)
                    }
                }
            }
        } else {
            # Legacy mode - update as before
            if ($PSBoundParameters.ContainsKey('ConfigStatus')) { $updates.ConfigStatus = $ConfigStatus }
            if ($PSBoundParameters.ContainsKey('ConfigProgress')) { $updates.ConfigProgress = $ConfigProgress }
            if ($PSBoundParameters.ContainsKey('AppStatus')) { $updates.AppStatus = $AppStatus }
            if ($PSBoundParameters.ContainsKey('AppProgress')) { $updates.AppProgress = $AppProgress }
            if ($PSBoundParameters.ContainsKey('MiniserverStatus')) { $updates.MiniserverStatus = $MiniserverStatus }
            if ($PSBoundParameters.ContainsKey('MiniserverProgress')) { $updates.MiniserverProgress = $MiniserverProgress }
        }
        
        # Update global data
        Update-ToastDataBinding -Updates $updates
        
        # Create or update toast
        if (-not $Global:PersistentToastInitialized) {
            # In parallel mode from a worker thread, skip initialization
            # But allow main thread to initialize even in parallel mode
            $isWorkerThread = $env:LOXONE_WORKER_NAME -or $env:LOXONE_IS_WORKER -eq "1"
            
            if ($env:LOXONE_PARALLEL_MODE -eq "1" -and $isWorkerThread) {
                Write-SafeLog -Level Debug -Message "Skipping toast initialization in parallel worker thread (should be handled by progress worker or main thread)"
                # Still mark as initialized to prevent further attempts in workers
                $Global:PersistentToastInitialized = $true
            } else {
                # Always initialize if not done yet - main thread or non-parallel mode
                Write-SafeLog -Level Debug -Message "Initializing toast (PersistentToastInitialized was FALSE, ParallelMode=$($env:LOXONE_PARALLEL_MODE), IsWorker=$isWorkerThread)"
                Initialize-Toast
                $Global:PersistentToastInitialized = $true
            }
        }
        elseif ($Global:PersistentToastInitialized) {
            Update-Toast
        }
        else {
            Write-SafeLog -Level Debug -Message "Toast not initialized and conditions not met for initialization"
        }
    }
    catch {
        Write-SafeLog -Level Error -Message "Error in Update-PersistentToast: $_"
    }
    finally {
        Exit-SafeFunction
    }
}

function Initialize-Toast {
    # Check for global force suppression first (for testing)
    # Only suppress if ForceToastSuppression is explicitly set to true
    if ($Global:ForceToastSuppression -eq $true) {
        Write-Verbose "Initialize-Toast: Suppressed by global override"
        $Global:PersistentToastInitialized = $true
        return $true
    }
    
    # Check module-level suppression
    if ($script:SuppressToastInit) {
        Write-Verbose "Initialize-Toast: Suppressed by module flag"
        $Global:PersistentToastInitialized = $true
        return $true
    }
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-SafeLog -Level Info -Message "Creating initial toast notification with buttons"
    
    try {
        # Reset any stale status from previous runs
        if ($Global:PersistentToastData) {
            $Global:PersistentToastData.ConfigStatus = "Waiting..."
            $Global:PersistentToastData.ConfigDuration = $null
            $Global:PersistentToastData.ConfigSymbol = $null
            $Global:PersistentToastData.AppStatus = "Waiting..."
            $Global:PersistentToastData.AppDuration = $null
            $Global:PersistentToastData.AppSymbol = $null
            $Global:PersistentToastData.AppTitle = "Loxone App"
            $Global:PersistentToastData.ConfigTitle = "Loxone Config"
            $Global:PersistentToastData.MiniserverStatus = "Waiting..."
            $Global:PersistentToastData.MiniserverDuration = $null
            $Global:PersistentToastData.MiniserverSymbol = $null
            $Global:PersistentToastData.MiniserversTitle = "Miniservers"
        }
        
        # Create components based on parallel mode
        $components = @()
        
        # Header text
        $components += New-BTText -Content "StatusText"
        
        # Check if we're in parallel mode and have workflow info
        # Try to get components from environment variable if global is not available
        $parallelComponents = if ($Global:ParallelWorkflowComponents) {
            $Global:ParallelWorkflowComponents
        } elseif ($env:LOXONE_PARALLEL_COMPONENTS) {
            try {
                $env:LOXONE_PARALLEL_COMPONENTS | ConvertFrom-Json
            } catch {
                Write-Log "Failed to parse LOXONE_PARALLEL_COMPONENTS: $_" -Level "WARN"
                $null
            }
        } else {
            $null
        }
        
        Write-Log "Toast init - Parallel mode: $($env:LOXONE_PARALLEL_MODE), Components: $($parallelComponents | ConvertTo-Json -Compress)" -Level "DEBUG"

        if ($env:LOXONE_PARALLEL_MODE -eq "1" -and $parallelComponents) {
            Write-Log "Creating component-specific progress bars" -Level "INFO"
            # Create progress bars based on what's actually being updated
            if ($parallelComponents.Config) {
                $components += New-BTProgressBar -Status "ConfigStatus" -Value "ConfigProgress" -Title "ConfigTitle"
            }
            if ($parallelComponents.App) {
                $components += New-BTProgressBar -Status "AppStatus" -Value "AppProgress" -Title "AppTitle"
            }
            if ($parallelComponents.Miniservers -gt 0) {
                $components += New-BTProgressBar -Status "MiniserverStatus" -Value "MiniserverProgress" -Title "MiniserversTitle"
            }
        } else {
            Write-Log "Using legacy 2 progress bars mode" -Level "INFO"
            # Legacy mode with 2 progress bars
            $components += New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress"
            $components += New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Workflow Progress"
        }
        
        $appLogo = Join-Path $PSScriptRoot '..\ms.png'
        
        # Create binding
        $binding = New-BTBinding -Children $components
        if (Test-Path $appLogo) {
            $image = New-BTImage -Source $appLogo -AppLogoOverride
            $binding = New-BTBinding -Children $components -AppLogoOverride $image
        }
        
        # Create visual
        $visual = New-BTVisual -BindingGeneric $binding
        
        # Create audio (silent)
        $audio = New-BTAudio -Silent
        
        # Create buttons
        $buttons = @(
            New-BTButton -Dismiss -Content 'Dismiss'
            New-BTButton -Snooze
        )
        $actions = New-BTAction -Buttons $buttons
        
        # Create content with Reminder scenario to prevent auto-dismiss
        $content = New-BTContent -Visual $visual -Audio $audio -Actions $actions `
            -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder) `
            -Duration ([Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
        
        # Build parameters
        $params = @{
            Content          = $content
            UniqueIdentifier = $Global:PersistentToastId
            DataBinding      = $Global:PersistentToastData
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        # Submit notification with scenario
        Submit-BTNotification @params
        $Global:PersistentToastInitialized = $true
        
        Write-SafeLog -Level Info -Message "Toast created successfully with Reminder scenario"
        
        # Give toast time to appear
        Start-Sleep -Milliseconds 500
    }
    catch {
        $Global:PersistentToastInitialized = $false
        Write-SafeLog -Level Error -Message "Failed to create toast: $_"
        throw
    }
    finally {
        Exit-SafeFunction
    }
}

function Update-Toast {
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-SafeLog -Level Debug -Message "Updating existing toast"
    
    try {
        $params = @{
            UniqueIdentifier = $Global:PersistentToastId
            DataBinding      = $Global:PersistentToastData
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        Update-BTNotification @params
        Write-SafeLog -Level Debug -Message "Toast updated successfully"
    }
    catch {
        Write-SafeLog -Level Error -Message "Failed to update toast: $_"
        throw
    }
    finally {
        Exit-SafeFunction
    }
}
#endregion

#region Helper Functions
#endregion

#region Final Status Toast
function Show-FinalStatusToast {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StatusMessage,
        [Parameter(Mandatory)][bool]$Success,
        [string]$LogFileToShow,
        [string]$TeamsLink,
        [bool]$LoxoneAppInstalled
    )
    
    # Check for global force suppression first (for testing)
    # Only suppress if ForceToastSuppression is explicitly set to true
    if ($Global:ForceToastSuppression -eq $true) {
        Write-Verbose "Show-FinalStatusToast: Suppressed by global override"
        return
    }
    
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Show-FinalStatusToast: Suppressed by SuppressToastInit"
        return
    }
    
    Enter-SafeFunction -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        Write-SafeLog -Level Info -Message "Creating final status toast (Success: $Success)"
        
        # Determine resources
        $appLogo = Join-Path (Join-Path $PSScriptRoot "..") $(if ($Success) { "ok.png" } else { "nok.png" })
        $toastId = "${Global:PersistentToastId}_Final"
        $logPath = if ($LogFileToShow) { $LogFileToShow } else { $Global:LogFile }
        
        # Build visual
        $text = New-BTText -Content $StatusMessage
        $image = if (Test-Path $appLogo) { New-BTImage -Source $appLogo -AppLogoOverride } else { $null }
        $binding = if ($image) { 
            New-BTBinding -Children $text -AppLogoOverride $image 
        } else { 
            New-BTBinding -Children $text 
        }
        $visual = New-BTVisual -BindingGeneric $binding
        
        # Build buttons
        $buttons = [System.Collections.Generic.List[object]]::new()
        $buttons.Add((New-BTButton -Dismiss -Content 'Close'))
        
        if ($logPath -and (Test-Path $logPath)) {
            $buttons.Add((New-BTButton -Content 'Open Log' -Arguments $logPath))
            
            if (-not $Success) {
                $chatScript = Join-Path $PSScriptRoot '..\Send-GoogleChat.ps1'
                if (Test-Path $chatScript) {
                    $command = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$chatScript`" -LogFilePath `"$logPath`""
                    $buttons.Add((New-BTButton -Content 'Send Log via Chat' -Arguments $command))
                }
            }
        }
        
        if ($LoxoneAppInstalled -and $buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Content 'APP' -Arguments 'loxone://'))
        }
        
        if ($TeamsLink -and $buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Content 'Team' -Arguments $TeamsLink))
        }
        
        if ($buttons.Count -lt 5) {
            $buttons.Add((New-BTButton -Snooze))
        }
        
        # Build content
        $actions = New-BTAction -Buttons $buttons
        $audio = New-BTAudio -Silent
        $content = New-BTContent -Visual $visual -Actions $actions -Audio $audio `
            -Scenario ([Microsoft.Toolkit.Uwp.Notifications.ToastScenario]::Reminder)
        
        # Submit
        $params = @{
            Content          = $content
            UniqueIdentifier = $toastId
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        Submit-BTNotification @params
        Write-SafeLog -Level Info -Message "Final status toast submitted successfully"
    }
    catch {
        Write-SafeLog -Level Error -Message "Failed to show final status toast: $_"
    }
    finally {
        Exit-SafeFunction
    }
}
#endregion


# Export functions
$functionsToExport = @(
    'Get-LoxoneToastAppId'
    'Initialize-LoxoneToastAppId'
    'Update-PersistentToast'
    'Show-FinalStatusToast'
    'Initialize-Toast'
    'Update-Toast'
    # Safe wrapper functions
    'Write-SafeLog'
    'Enter-SafeFunction' 
    'Exit-SafeFunction'
)


Export-ModuleMember -Function $functionsToExport
