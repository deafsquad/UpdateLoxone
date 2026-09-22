# Simple LiveProgress implementation for test runner
# This provides a cleaner implementation than the complex one in run-tests.ps1

function Initialize-SimpleProgress {
    param(
        [int]$TotalTests = 0,
        [string]$TestType = "Tests"
    )
    
    # Initialize global tracking variables
    $Global:LiveProgressStartTime = Get-Date
    $Global:LiveProgressTotalTests = $TotalTests
    $Global:LiveProgressCurrentTest = 0
    $Global:LiveProgressPassed = 0
    $Global:LiveProgressFailed = 0
    $Global:LiveProgressSkipped = 0
    $Global:LiveProgressToastId = "UpdateLoxoneTests_$(Get-Date -Format 'yyyyMMddHHmmss')"
    $Global:LiveProgressInitialized = $false
    
    # Create data binding for toast
    $Global:LiveProgressData = @{
        Title = "$TestType Progress"
        Status = "Initializing..."
        ProgressStatus = "0 / $TotalTests tests"
        ProgressValue = 0
        Details = "Starting test run..."
    }
    
    # Try to show initial toast
    try {
        if (Get-Command New-BTContent -ErrorAction SilentlyContinue) {
            Show-SimpleProgressToast
            $Global:LiveProgressInitialized = $true
        }
    } catch {
        Write-Verbose "Failed to initialize LiveProgress toast: $_"
    }
}

function Show-SimpleProgressToast {
    try {
        # Create simple toast components
        $title = New-BTText -Content "{Title}"
        $status = New-BTText -Content "{Status}"
        $progress = New-BTProgressBar -Status "{ProgressStatus}" -Value "{ProgressValue}"
        $details = New-BTText -Content "{Details}"
        
        # Add Loxone icon if available
        $appLogo = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'ms.png'
        if (Test-Path $appLogo) {
            $image = New-BTImage -Source $appLogo -AppLogoOverride
            $binding = New-BTBinding -Children $title, $status, $progress, $details -AppLogoOverride $image
        } else {
            $binding = New-BTBinding -Children $title, $status, $progress, $details
        }
        
        $visual = New-BTVisual -BindingGeneric $binding
        $audio = New-BTAudio -Silent
        $content = New-BTContent -Visual $visual -Audio $audio -Scenario Reminder -Duration Long
        
        # Get AppId
        $appId = if (Get-Command Get-LoxoneConfigToastAppId -ErrorAction SilentlyContinue) {
            Get-LoxoneConfigToastAppId
        } else {
            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        }
        
        # Submit notification
        Submit-BTNotification -Content $content -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressData -AppId $appId
    } catch {
        Write-Verbose "Failed to show progress toast: $_"
    }
}

function Update-SimpleProgress {
    param(
        [string]$TestName = "",
        [ValidateSet('Passed', 'Failed', 'Skipped')]
        [string]$Result = 'Passed',
        [string]$Category = ""
    )
    
    if (-not $Global:LiveProgressInitialized) {
        return
    }
    
    # Update counters
    $Global:LiveProgressCurrentTest++
    switch ($Result) {
        'Passed' { $Global:LiveProgressPassed++ }
        'Failed' { $Global:LiveProgressFailed++ }
        'Skipped' { $Global:LiveProgressSkipped++ }
    }
    
    # Calculate progress
    $progress = if ($Global:LiveProgressTotalTests -gt 0) {
        [math]::Round(($Global:LiveProgressCurrentTest / $Global:LiveProgressTotalTests), 2)
    } else { 0 }
    
    # Calculate runtime
    $runtime = (Get-Date) - $Global:LiveProgressStartTime
    $runtimeStr = "{0}:{1:00}" -f [math]::Floor($runtime.TotalMinutes), ($runtime.Seconds)
    
    # Update data binding
    $Global:LiveProgressData.Status = "Running $Category tests | $runtimeStr"
    $Global:LiveProgressData.ProgressStatus = "$($Global:LiveProgressCurrentTest) / $($Global:LiveProgressTotalTests) tests"
    $Global:LiveProgressData.ProgressValue = $progress
    $Global:LiveProgressData.Details = @(
        "✅ Passed: $($Global:LiveProgressPassed)"
        "❌ Failed: $($Global:LiveProgressFailed)"
        "⏭️ Skipped: $($Global:LiveProgressSkipped)"
    ) -join "`n"
    
    # Update toast
    try {
        $appId = if (Get-Command Get-LoxoneConfigToastAppId -ErrorAction SilentlyContinue) {
            Get-LoxoneConfigToastAppId
        } else {
            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        }
        
        Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressData -AppId $appId -ErrorAction SilentlyContinue
    } catch {
        # Silently ignore update failures
    }
}

function Complete-SimpleProgress {
    param(
        [int]$TotalPassed = 0,
        [int]$TotalFailed = 0,
        [int]$TotalSkipped = 0
    )
    
    if (-not $Global:LiveProgressInitialized) {
        return
    }
    
    # Calculate final runtime
    $runtime = (Get-Date) - $Global:LiveProgressStartTime
    $runtimeStr = "{0}:{1:00}" -f [math]::Floor($runtime.TotalMinutes), ($runtime.Seconds)
    
    # Determine status
    $status = if ($TotalFailed -eq 0) { "✅ All tests passed!" } else { "❌ Some tests failed" }
    
    # Update for final display
    $Global:LiveProgressData.Status = "$status | Total time: $runtimeStr"
    $Global:LiveProgressData.ProgressStatus = "$($TotalPassed + $TotalFailed + $TotalSkipped) tests completed"
    $Global:LiveProgressData.ProgressValue = 1.0
    $Global:LiveProgressData.Details = @(
        "✅ Passed: $TotalPassed"
        "❌ Failed: $TotalFailed"
        "⏭️ Skipped: $TotalSkipped"
    ) -join "`n"
    
    # Final update
    try {
        $appId = if (Get-Command Get-LoxoneConfigToastAppId -ErrorAction SilentlyContinue) {
            Get-LoxoneConfigToastAppId
        } else {
            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        }
        
        Update-BTNotification -UniqueIdentifier $Global:LiveProgressToastId -DataBinding $Global:LiveProgressData -AppId $appId -ErrorAction SilentlyContinue
    } catch {
        # Silently ignore
    }
    
    # Clean up globals
    Remove-Variable -Name LiveProgressStartTime -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressTotalTests -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressCurrentTest -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressPassed -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressFailed -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressSkipped -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressToastId -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressInitialized -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LiveProgressData -Scope Global -ErrorAction SilentlyContinue
}

# Export functions
Export-ModuleMember -Function Initialize-SimpleProgress, Update-SimpleProgress, Complete-SimpleProgress