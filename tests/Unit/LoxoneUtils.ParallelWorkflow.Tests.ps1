# Unit tests for LoxoneUtils.ParallelWorkflow module

BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
    # Set up test mode BEFORE importing modules
    $Global:IsTestRun = $true
    $env:PESTER_TEST_RUN = "1"
    $env:LOXONE_TEST_MODE = "1"
    
    # Load RunAsUser mocks BEFORE importing the module to prevent type compilation
    . (Join-Path $PSScriptRoot "LoxoneUtils.RunAsUser.TestMocks.ps1")
    
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Load ALL necessary mocks to prevent real operations
    . (Join-Path $PSScriptRoot "LoxoneUtils.Network.TestMocks.ps1")
    . (Join-Path $PSScriptRoot "LoxoneUtils.Installation.TestMocks.ps1")
    . (Join-Path $PSScriptRoot "LoxoneUtils.Miniserver.TestMocks.ps1")
    . (Join-Path $PSScriptRoot "LoxoneUtils.Toast.TestMocks.ps1")
    . (Join-Path $PSScriptRoot "LoxoneUtils.ParallelWorkflow.ThreadJobMocks.ps1")
    . (Join-Path $PSScriptRoot "LoxoneUtils.ParallelWorkflow.TestMocks.ps1")
}

AfterAll {
    # Clean up
    Remove-Variable -Name IsTestRun -Scope Global -ErrorAction SilentlyContinue
    Remove-Item env:PESTER_TEST_RUN -ErrorAction SilentlyContinue
    Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
}

Describe "Start-ParallelWorkflow Function" -Tag 'ParallelWorkflow' {
    
    BeforeEach {
        # Clear any existing parallel mode flag
        Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
        
        # Set up a test log file
        $guid = [System.Guid]::NewGuid().ToString()
        $Global:LogFile = Join-Path $TestDrive "test_parallel_$guid.log"
        "# Test log file" | Out-File $Global:LogFile -Encoding UTF8
    }
    
    AfterEach {
        Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
        Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
    }
    
    Context "Basic Functionality" {
        It "Sets parallel mode environment variable" -Skip {
            # Skip: Start-ParallelWorkflow may trigger RunAsUser module loading which requires elevated privileges
            # Create minimal workflow definition
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            # Mock the internal functions
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                return @{
                    Success = $true
                    TotalDuration = 0
                }
            }
            
            # Run the workflow
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            # Verify result
            $result | Should -Not -BeNullOrEmpty
            $result.Success | Should -Be $true
        }
        
        It "Returns success when no work to do" -Skip {
            # Skip: Start-ParallelWorkflow may trigger RunAsUser module loading which requires elevated privileges
            # Empty workflow definition
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            # Mock the internal functions
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                return @{
                    Success = $true
                    TotalDuration = 0
                }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            $result.Success | Should -Be $true
            $result.TotalDuration | Should -BeGreaterOrEqual 0
        }
        
        It "Cleans up parallel mode flag on completion" -Skip {
            # Skip: Start-ParallelWorkflow may trigger RunAsUser module loading which requires elevated privileges
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                # Verify flag is set during execution
                $env:LOXONE_PARALLEL_MODE | Should -Be "1"
                return @{
                    Success = $true
                    TotalDuration = 0
                }
            }
            
            Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            # Flag should be cleared after completion
            $env:LOXONE_PARALLEL_MODE | Should -BeNullOrEmpty
        }
    }
    
    Context "Worker Management" {
        It "Only starts workers when there's work" -Skip {
            # Skip: Start-ParallelWorkflow may trigger RunAsUser module loading which requires elevated privileges
            # No updates needed
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker { 
                throw "Download worker should not be started"
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-InstallWorker { 
                throw "Install worker should not be started"
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-MiniserverWorker { 
                return $null 
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                throw "Progress worker should not be started"
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                param($WorkerJobs, $WorkflowDefinition, $Pipeline)
                # Verify no workers were started
                $WorkerJobs | Should -BeNullOrEmpty
                
                return @{
                    Success = $true
                    TotalDuration = 0
                }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            $result.Success | Should -Be $true
        }
        
        # Skip: ThreadJob cmdlet isolation prevents mocking - real jobs would be created
        It "Starts download/install workers for software updates" -Skip {
            # Config update needed
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.com/config.zip"
                    OutputPath = "C:\test\config.zip"
                    CRC = "12345678"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            $downloadWorkerStarted = $false
            $installWorkerStarted = $false
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker { 
                $script:downloadWorkerStarted = $true
                return [PSCustomObject]@{ Id = 1; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-InstallWorker { 
                $script:installWorkerStarted = $true
                return [PSCustomObject]@{ Id = 2; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-MiniserverWorker { 
                return $null 
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                return [PSCustomObject]@{ Id = 3; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                param($WorkerJobs, $WorkflowDefinition, $Pipeline)
                # Verify correct workers were started
                $WorkerJobs | Should -Not -BeNullOrEmpty
                $WorkerJobs.Count | Should -BeGreaterThan 0
                
                return @{
                    Success = $true
                    TotalDuration = 1
                }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            $result.Success | Should -Be $true
        }
        
        # Skip: ThreadJob cmdlet isolation prevents mocking - real jobs would be created
        It "Starts miniserver worker when miniservers defined" -Skip {
            # Miniservers to update
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @(
                    @{
                        IP = "192.168.1.100"
                        Credential = $null
                        UpdateLevel = "Release"
                    }
                )
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker { 
                throw "Download worker should not be started"
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-InstallWorker { 
                throw "Install worker should not be started"
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-MiniserverWorker { 
                return [PSCustomObject]@{ Id = 4; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                return [PSCustomObject]@{ Id = 5; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                param($WorkerJobs, $WorkflowDefinition, $Pipeline)
                # Verify correct workers were started (miniserver worker should be present)
                $WorkerJobs | Should -Not -BeNullOrEmpty
                $WorkerJobs.Count | Should -BeGreaterOrEqual 1
                
                return @{
                    Success = $true
                    TotalDuration = 2
                }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            $result.Success | Should -Be $true
        }
    }
    
    Context "Error Handling" {
        # Skip: Would create real ThreadJobs for progress worker
        It "Cleans up parallel mode flag on error" -Skip {
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.com/config.zip"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            # Mock a function that is actually called to throw an error
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker {
                throw "Test error in download worker"
            }
            
            { Start-ParallelWorkflow -WorkflowDefinition $workflowDef } | Should -Throw
            
            # Flag should still be cleared
            $env:LOXONE_PARALLEL_MODE | Should -BeNullOrEmpty
        }
        
        # Skip: ThreadJob cmdlet isolation prevents mocking - real jobs would be created
        It "Returns failure result when workflow fails" -Skip {
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.com/config.zip"
                    OutputPath = "C:\test\config.zip"
                    CRC = "12345678"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker { 
                return [PSCustomObject]@{ Id = 1; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-InstallWorker { 
                return [PSCustomObject]@{ Id = 2; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                return [PSCustomObject]@{ Id = 3; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                return @{
                    Success = $false
                    TotalDuration = 5
                    Errors = @("Download failed")
                }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            $result.Success | Should -Be $false
            $result.Errors | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Concurrency Parameters" {
        # Skip: ThreadJob cmdlet isolation prevents mocking - real jobs would be created
        It "Respects MaxConcurrency parameter" -Skip {
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.com/config.zip"
                    OutputPath = "C:\test\config.zip"
                    CRC = "12345678"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $TestDrive
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ComponentDownloadWorker { 
                param($Pipeline, $Component, $DownloadInfo, $ScriptSaveFolder, $ModulePath)
                # MaxConcurrency is not a parameter for Start-ComponentDownloadWorker
                return [PSCustomObject]@{ Id = 1; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-InstallWorker { 
                param($Pipeline, $MaxConcurrency, $DownloadWorkers)
                $MaxConcurrency | Should -Be 1  # InstallWorker always uses MaxConcurrency=1
                return [PSCustomObject]@{ Id = 2; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                return [PSCustomObject]@{ Id = 3; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                return @{ Success = $true; TotalDuration = 0 }
            }
            
            Start-ParallelWorkflow -WorkflowDefinition $workflowDef -MaxConcurrency 2
        }
        
        # Skip: ThreadJob cmdlet isolation prevents mocking - real jobs would be created
        It "Respects MaxMSConcurrency parameter" -Skip {
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @(
                    @{ IP = "192.168.1.100"; Credential = $null; UpdateLevel = "Release" }
                    @{ IP = "192.168.1.101"; Credential = $null; UpdateLevel = "Release" }
                )
            }
            
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Initialize-ProgressTracking {}
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-MiniserverWorker { 
                param($WorkflowDefinition, $MaxConcurrency)
                $MaxConcurrency | Should -Be 1
                return [PSCustomObject]@{ Id = 4; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Start-ProgressWorker { 
                return [PSCustomObject]@{ Id = 5; State = 'Running' }
            }
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Watch-DirectThreadJobs {
                return @{ Success = $true; TotalDuration = 0 }
            }
            
            Start-ParallelWorkflow -WorkflowDefinition $workflowDef -MaxMSConcurrency 1
        }
    }
}

Describe "Helper Functions" -Tag 'ParallelWorkflow' {
    
    Context "Test-WorkflowComplete" {
        BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
}
            # Internal functions are not easily testable from outside the module
            # Skip these tests or mock at a higher level
            $script:skipInternal = $true
        }
        
        It "Returns true when all queues are empty and no work enabled" -Skip {
            # This test is skipped because Test-WorkflowComplete is an internal function
            # that cannot be easily tested from outside the module
        }
        
        It "Returns false when download queue has items" -Skip {
            # This test is skipped because Test-WorkflowComplete is an internal function
            # that cannot be easily tested from outside the module
        }
    }
    
    Context "Update-MiniserverProgress" {
        BeforeAll {
    # Performance optimization: Skip module import if already loaded
    if (-not $Global:LoxoneUtilsPreloaded) {
        # Module not preloaded, import it
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        # Module already loaded, just ensure it's available in this scope
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    
    # Set flag to suppress toast initialization
    $Global:SuppressLoxoneToastInit = $true
    
    # Get the internal function if accessible
    $module = Get-Module LoxoneUtils.ParallelWorkflow
    $updateMSProgress = & $module { ${function:Update-MiniserverProgress} } -ErrorAction SilentlyContinue
}

Describe "Internal Functions" -Tag 'ParallelWorkflow' {
        
    It "Updates miniserver state in workflow progress" -Skip:(-not $updateMSProgress) {
            # Set up workflow state
            Mock -ModuleName LoxoneUtils.ParallelWorkflow Get-Variable {
                return [PSCustomObject]@{
                    Value = @{
                        Progress = @{
                            MiniserverUpdates = @{
                                States = @{
                                    "192.168.1.100" = @{
                                        IP = "192.168.1.100"
                                        Stage = "Init"
                                        LastStateChange = Get-Date
                                    }
                                }
                            }
                        }
                    }
                }
            } -ParameterFilter { $Name -eq 'WorkflowState' -and $Scope -eq 'Script' }
            
            & $updateMSProgress -IP "192.168.1.100" -Stage "Update"
            
            # Verify state was updated
            Should -Invoke -CommandName Get-Variable -ModuleName LoxoneUtils.ParallelWorkflow
        }
    }
}
