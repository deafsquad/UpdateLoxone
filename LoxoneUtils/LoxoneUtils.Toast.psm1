# Optimized LoxoneUtils.Toast Module
# Key improvements:
# 1. Reduced redundant logging
# 2. Centralized parameter validation
# 3. Simplified data binding updates
# 4. Better separation of concerns
# 5. Removed duplicate code blocks

#region Module Initialization
# Test mode detection - must be at the very top
$script:IsTestMode = ($env:PESTER_TEST_RUN -eq "1") -or 
                     ($Global:IsTestRun -eq $true) -or 
                     ($env:LOXONE_TEST_MODE -eq "1")

if ($script:IsTestMode) {
    Write-Verbose "Test mode detected - Toast operations will be mocked"
    
    # Always create mock BurntToast functions in test mode to prevent real toasts
    # Remove existing BurntToast commands if loaded
    $btCommands = @('New-BTText', 'New-BTProgressBar', 'New-BTImage', 'New-BTBinding',
                    'New-BTVisual', 'New-BTAudio', 'New-BTButton', 'New-BTAction',
                    'New-BTContent', 'Submit-BTNotification', 'Update-BTNotification')
    
    foreach ($cmd in $btCommands) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) {
            Remove-Item "function:$cmd" -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Create mock functions
    function New-BTText { 
        param($Content) 
        return @{Type='Text'; Content=$Content} 
    }
    function New-BTProgressBar { 
        param($Status, $Value, $Title) 
        return @{Type='ProgressBar'; Status=$Status; Value=$Value; Title=$Title} 
    }
    function New-BTImage { 
        param($Source, [switch]$AppLogoOverride) 
        return @{Type='Image'; Source=$Source; AppLogoOverride=$AppLogoOverride} 
    }
    function New-BTBinding { 
        param($Children, $AppLogoOverride) 
        return @{Type='Binding'; Children=$Children; AppLogoOverride=$AppLogoOverride} 
    }
    function New-BTVisual { 
        param($BindingGeneric) 
        return @{Type='Visual'; Binding=$BindingGeneric} 
    }
    function New-BTAudio { 
        param([switch]$Silent) 
        return @{Type='Audio'; Silent=$Silent} 
    }
    function New-BTButton { 
        param($Content, $Arguments, [switch]$Dismiss, [switch]$Snooze) 
        return @{Type='Button'; Content=$Content; Arguments=$Arguments; Dismiss=$Dismiss; Snooze=$Snooze} 
    }
    function New-BTAction { 
        param($Buttons) 
        return @{Type='Action'; Buttons=$Buttons} 
    }
    function New-BTContent { 
        param($Visual, $Audio, $Actions, $ActivationType, $Scenario, $Duration, $DataBinding) 
        return @{Type='Content'; Visual=$Visual; Audio=$Audio; Actions=$Actions; Scenario=$Scenario; Duration=$Duration; DataBinding=$DataBinding} 
    }
    function Submit-BTNotification { 
        param($Content, $UniqueIdentifier, $AppId, $DataBinding, $ErrorAction)
        Write-Verbose "[MOCK] Would show toast: $UniqueIdentifier"
        $Global:MockToastShown = $true
        $Global:LastMockToastId = $UniqueIdentifier
        $Global:LastMockToastContent = $Content
        $Global:LastMockToastDataBinding = $DataBinding
    }
    function Update-BTNotification {
        param($UniqueIdentifier, $DataBinding, $AppId, $ErrorAction)
        Write-Verbose "[MOCK] Would update toast: $UniqueIdentifier"
        $Global:MockToastUpdated = $true
        $Global:LastMockToastUpdate = $DataBinding
    }
    Write-Verbose "Created mock BurntToast functions"
}

# Check if toast initialization is suppressed
$script:SuppressToastInit = $Global:SuppressLoxoneToastInit -eq $true
if ($script:SuppressToastInit) {
    Write-Verbose "Toast module initialization suppressed by Global:SuppressLoxoneToastInit"
    # Don't return - we still need to export functions
}

$script:IsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem

if (-not $script:SuppressToastInit -and -not $script:IsSystem -and -not $script:IsTestMode -and -not (Get-Module -Name BurntToast -ListAvailable)) {
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
    }
}

# Initialize global state only if not suppressed OR in test mode
if (-not $script:SuppressToastInit -or $script:IsTestMode) {
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
if (-not $script:SuppressToastInit -or $script:IsTestMode) {
    if (-not (Test-Path variable:Global:PersistentToastData)) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level Debug -Message "Initializing Global:PersistentToastData for the first time"
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
            DownloadSizeLine      = ""
        }
    } else {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level Debug -Message "Global:PersistentToastData already exists - preserving existing object"
        }
    }
}
#endregion

#region Helper Functions
function Get-ParameterSummary {
    param([hashtable]$BoundParameters)
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
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
        Exit-Function
    }
}
#endregion

#region AppId Management
function Get-LoxoneToastAppId {
    [CmdletBinding()]
    param([string]$PreFoundPath)
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $loxonePath = $PreFoundPath
        if (-not $loxonePath) {
            Write-Log -Level Debug -Message "No pre-found path provided. Searching registry..."
            try {
                $loxonePath = Get-LoxoneExePath -ErrorAction SilentlyContinue
            } catch {
                Write-Log -Level Warn -Message "Error calling Get-LoxoneExePath: $($_.Exception.Message)"
            }
        }
        
        if ($loxonePath) {
            Write-Log -Level Info -Message "Using hardcoded Loxone Config AppId"
            return '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Loxone\LoxoneConfig\LoxoneConfig.exe'
        }
        
        Write-Log -Level Info -Message "No Loxone Config found. Using default AppId."
        return $null
    }
    finally { Exit-Function }
}

function Initialize-LoxoneToastAppId {
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Initialize-LoxoneToastAppId: Suppressed by SuppressToastInit"
        return
    }
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        $script:ResolvedToastAppId = Get-LoxoneToastAppId -PreFoundPath $script:InstalledExePath
        Write-Log -Level Debug -Message "Resolved Toast AppId: '$($script:ResolvedToastAppId | Out-String)'"
    }
    finally { Exit-Function }
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
    #>
    param(
        [hashtable]$Updates,
        [switch]$PreserveExisting
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Check test mode
        if ($script:IsTestMode) {
            Write-Log -Message "[MOCK] Updating toast data in test mode" -Level DEBUG
            # Don't return early - we still need to update the data for tests
        }
        if (-not $Updates) { return }
    
    # Verify we're not accidentally trying to replace the entire object
    if ($Updates -eq $Global:PersistentToastData) {
        Write-Log -Level Error -Message "CRITICAL: Attempted to replace entire PersistentToastData object!"
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
        Exit-Function
    }
}

function Build-StatusText {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Build detailed info as primary content (reorganized from step info)
        $details = @()
        if ($Params.DownloadSpeed) { $details += "Speed: $($Params.DownloadSpeed)" }
        if ($Params.DownloadRemainingTime) { $details += "Time Rem: $($Params.DownloadRemainingTime)" }
        if ($Params.DownloadSizeProgress) { $details += "Size: $($Params.DownloadSizeProgress)" }
        
        if ($details.Count -gt 0) {
            return $details -join "`n"
        }
        
        # When no details available, show enhanced context-based messages
        if ($Params.StepNumber -and $Params.TotalSteps -and $Params.StepName) {
            # Check if this is the final step
            if ($Params.StepNumber -eq $Params.TotalSteps) {
                # Get success/error status from parameters
                $success = -not ($Params.ContainsKey('ErrorOccurred') -and $Params.ErrorOccurred)
                $statusSymbol = if ($success) { "✓" } else { "✗" }
                
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
                return "✓ All downloads completed`nVerifying file integrity..."
            }
            elseif ($stepName -like '*initial*' -or $stepName -like '*check*') {
                return "🔍 Checking for available updates`nConnecting to update servers..."
            }
            elseif ($stepName -like '*download*') {
                return "⬇️ Preparing file downloads`nValidating download sources..."
            }
            elseif ($stepName -like '*config*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "⚙️ Installing $displayName`nUpdating system components..."
            }
            elseif ($stepName -like '*app*' -and $stepName -like '*install*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "⚙️ Installing $displayName`nConfiguring application settings..."
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*config*') {
                $displayName = $script:StepCategories['Conf'].DisplayName
                return "📦 Extracting $displayName`nPreparing installation files..."
            }
            elseif ($stepName -like '*extract*' -and $stepName -like '*app*') {
                $displayName = $script:StepCategories['APP'].DisplayName
                return "📦 Extracting $displayName`nPreparing application files..."
            }
            elseif ($stepName -like '*miniserver*' -or $stepName -like '*ms*') {
                return "🔄 Updating Miniserver firmware`nEstablishing secure connection..."
            }
            elseif ($stepName -like '*finali*' -or $stepName -like '*complet*') {
                return "🏁 Finalizing installation`nCleaning up temporary files..."
            }
            else {
                return "⏳ Processing workflow step`nPlease wait..."
            }
        }
        
        # Initial state: clear any previous run text
        return "🚀 Initializing update process`nPreparing system checks..."
    }
    finally {
        Exit-Function
    }
}

function Build-ProgressBarStatus {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Active download in progress
        if ($Params.DownloadFileName) {
            if ($Params.DownloadNumber -and $Params.TotalDownloads) {
                return "Download $($Params.DownloadNumber)/$($Params.TotalDownloads): $($Params.DownloadFileName)"
            }
            return "Download: $($Params.DownloadFileName)"
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
        Exit-Function
    }
}

function Build-OverallProgressStatus {
    param(
        [hashtable]$Params
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
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
        Exit-Function
    }
}

function Reset-RuntimeTracking {
    # Reset all timing variables for a new process
    $Global:ScriptStartTime = Get-Date
    $Global:StepTimings = @{}
    $Global:StepRuntimes = @{}
    $Global:LastStepKey = $null
    Write-Log -Level Debug -Message "Reset runtime tracking - new process started"
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
        
        Write-Log -Level Debug -Message "Accumulated time for $previousStep`: $runtime min (total: $($Global:StepRuntimes[$previousStep]) min)"
    }
    
    # Track active category timing
    if (-not $Global:StepTimings.ContainsKey($stepKey)) {
        # First time seeing this category - start timing
        $Global:StepTimings[$stepKey] = $now
        Write-Log -Level Debug -Message "Started timing for category: $stepKey ($StepName)"
    }
    elseif ($previousStep -eq $stepKey) {
        # Same category continuing
        Write-Log -Level Debug -Message "Continuing category $stepKey with: $StepName"
    }
    else {
        # Returning to a category that was tracked before
        $Global:StepTimings[$stepKey] = $now
        Write-Log -Level Debug -Message "Resumed timing for category: $stepKey ($StepName)"
    }
    
    # Remember the current category for next call
    $Global:LastStepKey = $stepKey
}

function Build-RuntimeSummary {
    param(
        [int]$CurrentStep,
        [string]$StepName
    )
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
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
            
            Write-Log -Level Debug -Message "Final accumulation for $lastKey`: $runtime min (total: $($Global:StepRuntimes[$lastKey]) min)"
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
        Exit-Function
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
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
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
        Exit-Function
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
        # Context (Required)
        [Parameter(Mandatory)][bool]$IsInteractive,
        [Parameter(Mandatory)][bool]$ErrorOccurred,
        [bool]$AnyUpdatePerformed = $false,
        [bool]$CallingScriptIsInteractive = $false,
        [bool]$CallingScriptIsSelfInvoked = $false
    )
    
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Update-PersistentToast: Suppressed by SuppressToastInit"
        return
    }
    
    Start-Sleep -Milliseconds 50  # Small delay for visibility
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    
    try {
        # Verify data binding object still exists (safety check)
        if (-not (Test-Path variable:Global:PersistentToastData)) {
            Write-Log -Level Error -Message "CRITICAL: Global:PersistentToastData was deleted! This should never happen."
            throw "PersistentToastData was deleted - toast binding is broken"
        }
        
        # Log parameter summary (consolidated)
        $paramSummary = Get-ParameterSummary $PSBoundParameters
        Write-Log -Level Debug -Message "Update-PersistentToast called with $($PSBoundParameters.Count) parameters: $($paramSummary | ConvertTo-Json -Compress)"
        
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
        
        # Update global data
        Update-ToastDataBinding -Updates $updates
        
        # Determine if we should defer initial creation
        $shouldDefer = $CallingScriptIsSelfInvoked
        
        # Create or update toast
        if (-not $Global:PersistentToastInitialized -and -not $shouldDefer) {
            Initialize-Toast
        }
        elseif ($Global:PersistentToastInitialized) {
            Update-Toast
        }
        else {
            Write-Log -Level Debug -Message "Toast update deferred (self-invoked context)"
        }
    }
    catch {
        Write-Log -Level Error -Message "Error in Update-PersistentToast: $_"
    }
    finally {
        Exit-Function
    }
}

function Initialize-Toast {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Info -Message "Creating initial toast notification with buttons"
    
    try {
        # Check test mode
        if ($script:IsTestMode) {
            Write-Log -Message "[MOCK] Would initialize toast notification" -Level INFO
            $Global:PersistentToastInitialized = $true
            Exit-Function
            return
        }
        # Create components
        $text = New-BTText -Content "StatusText"
        $progressBar1 = New-BTProgressBar -Status "ProgressBarStatus" -Value "ProgressBarValue" -Title "Task Progress"
        $progressBar2 = New-BTProgressBar -Status "OverallProgressStatus" -Value "OverallProgressValue" -Title "Workflow Progress"
        $appLogo = Join-Path $PSScriptRoot '..\ms.png'
        
        # Create binding
        $binding = New-BTBinding -Children $text, $progressBar1, $progressBar2
        if (Test-Path $appLogo) {
            $image = New-BTImage -Source $appLogo -AppLogoOverride
            $binding = New-BTBinding -Children $text, $progressBar1, $progressBar2 -AppLogoOverride $image
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
        
        Write-Log -Level Info -Message "Toast created successfully with Reminder scenario"
    }
    catch {
        $Global:PersistentToastInitialized = $false
        Write-Log -Level Error -Message "Failed to create toast: $_"
        throw
    }
    finally {
        Exit-Function
    }
}

function Update-Toast {
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    Write-Log -Level Debug -Message "Updating existing toast"
    
    try {
        # Check test mode
        if ($script:IsTestMode) {
            Write-Log -Message "[MOCK] Updating toast data in test mode" -Level DEBUG
            # Don't return early - we still need to update the data for tests
        }
        $params = @{
            UniqueIdentifier = $Global:PersistentToastId
            DataBinding      = $Global:PersistentToastData
            ErrorAction      = 'Stop'
        }
        
        if ($script:ResolvedToastAppId) {
            $params.AppId = $script:ResolvedToastAppId
        }
        
        Update-BTNotification @params
        Write-Log -Level Debug -Message "Toast updated successfully"
    }
    catch {
        Write-Log -Level Error -Message "Failed to update toast: $_"
        throw
    }
    finally {
        Exit-Function
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
    
    # Exit early if suppressed
    if ($script:SuppressToastInit) {
        Write-Verbose "Show-FinalStatusToast: Suppressed by SuppressToastInit"
        return
    }
    
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.MyCommand.Definition -LineNumber $MyInvocation.ScriptLineNumber
    try {
        # Check test mode
        if ($script:IsTestMode) {
            Write-Log -Message "[MOCK] Would show final status toast: $Status" -Level INFO
            Exit-Function
            return
        }
        Write-Log -Level Info -Message "Creating final status toast (Success: $Success)"
        
        # Determine resources
        $appLogo = Join-Path (Join-Path $PSScriptRoot "..") $(if ($Success) { "ok.png" } else { "nok.png" })
        $toastId = "${Global:PersistentToastId}_Final"
        $logPath = if ($LogFileToShow) { $LogFileToShow } else { $script:LogFilePath }
        
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
        Write-Log -Level Info -Message "Final status toast submitted successfully"
    }
    catch {
        Write-Log -Level Error -Message "Failed to show final status toast: $_"
    }
    finally {
        Exit-Function
    }
}
#endregion


# Export functions
$functionsToExport = @(
    'Get-LoxoneToastAppId'
    'Initialize-LoxoneToastAppId'
    'Update-PersistentToast'
    'Show-FinalStatusToast'
)

# In test mode, also export the mock BurntToast functions
if ($script:IsTestMode) {
    $functionsToExport += @(
        'New-BTText', 'New-BTProgressBar', 'New-BTImage', 'New-BTBinding',
        'New-BTVisual', 'New-BTAudio', 'New-BTButton', 'New-BTAction',
        'New-BTContent', 'Submit-BTNotification', 'Update-BTNotification'
    )
}

Export-ModuleMember -Function $functionsToExport
