# Global mocks for WorkflowSteps functions to prevent parameter prompts during tests

# Check if running in test mode
if (-not $env:PESTER_TEST_RUN) {
    $env:PESTER_TEST_RUN = "1"
}

# Mock Initialize-ScriptWorkflow to prevent parameter prompts
# Create the function regardless of whether it exists
# Remove Mandatory from all parameters to prevent prompts
function global:Initialize-ScriptWorkflow {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$false)]
            [hashtable]$BoundParameters = @{},
            
            [Parameter(Mandatory=$false)]
            [string]$PSScriptRoot = $PWD.Path,
            
            [Parameter(Mandatory=$false)]
            [System.Management.Automation.InvocationInfo]$MyInvocation = $null
        )
        
        Write-Verbose "[GLOBAL-MOCK] Initialize-ScriptWorkflow called"
        
        # Return a mock workflow context
        return [PSCustomObject]@{
            Succeeded = $true
            Reason = ""
            Error = $null
            Component = "Initialization"
            ScriptSaveFolder = $PSScriptRoot
            LogFile = Join-Path $env:TEMP "test.log"
            LogDir = $env:TEMP
            IsAdminRun = $false
            IsElevatedInstance = $false
            IsInteractive = $true
            IsRunningAsSystem = $false
            IsSelfInvokedForUpdateCheck = $false
            InitialInstalledConfigVersion = "14.0.0.0"
            InstalledConfigExePath = "C:\Program Files\Loxone\LoxoneConfig\LoxoneConfig.exe"
            InitialLoxoneAppDetails = [PSCustomObject]@{
                FileVersion = "14.0.0.0"
                FilePath = "C:\Program Files\Loxone\LoxoneApp\LoxoneApp.exe"
            }
            DownloadDir = Join-Path $env:TEMP "LoxoneDownloads"
            MSListPath = Join-Path $PSScriptRoot "UpdateLoxoneMSList.txt"
            Constants = @{}
            TaskName = "LoxoneUpdateTask"
            LoxoneIconPath = $null
            Params = $BoundParameters
            MyScriptRoot = $PSScriptRoot
            LoxoneUtilsModulePath = (Get-Module LoxoneUtils -ErrorAction SilentlyContinue).Path
            SystemCanLog = $false
        }
}

# Mock Initialize-UpdatePipelineData to prevent it from calling Initialize-ScriptWorkflow
# Create the function regardless of whether it exists
function global:Initialize-UpdatePipelineData {
        [CmdletBinding()]
        param (
            [Parameter()]
            [PSCustomObject]$WorkflowContext,
            
            [Parameter()]
            [PSCustomObject]$Prerequisites
        )
        
        Write-Verbose "[GLOBAL-MOCK] Initialize-UpdatePipelineData called"
        
        # Return a mock pipeline data object
        return [PSCustomObject]@{
            Succeeded = $true
            Component = "UpdatePipelineData"
            Error = $null
            UpdateTargetsInfo = [System.Collections.ArrayList]@()
            TotalWeight = 10
            TotalSteps = 5
            TotalDownloads = 2
            InitialCheckWeight = 1
        }
}

Write-Host "Global WorkflowSteps mocks loaded - no parameter prompts will occur" -ForegroundColor Green
$Global:WorkflowStepsMocksLoaded = $true