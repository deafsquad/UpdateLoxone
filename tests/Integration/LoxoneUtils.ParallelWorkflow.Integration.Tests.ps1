# Integration tests for LoxoneUtils.ParallelWorkflow module
# Tests actual worker coordination and data flow between components

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
    # Import the module
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Set up test mode
    $Global:IsTestRun = $true
    $env:PESTER_TEST_RUN = "1"
    $env:LOXONE_TEST_MODE = "1"
    
    # Set up test directory
    $script:TestDir = Join-Path $TestDrive "ParallelWorkflowIntegration"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
    
    # Set up log file
    $Global:LogFile = Join-Path $script:TestDir "integration_test.log"
    "# Integration test log" | Out-File $Global:LogFile -Encoding UTF8
    
    # Load test mocks to prevent actual network/installation operations
    $mockPath = Join-Path (Split-Path -Parent $PSScriptRoot) "Unit"
    
    # Load Network mocks
    . (Join-Path $mockPath "LoxoneUtils.Network.TestMocks.ps1")
    
    # Load Installation mocks  
    . (Join-Path $mockPath "LoxoneUtils.Installation.TestMocks.ps1")
    
    # Load System mocks
    . (Join-Path $mockPath "LoxoneUtils.System.TestMocks.ps1")
    
    # Load Logging mocks
    . (Join-Path $mockPath "LoxoneUtils.Logging.TestMocks.ps1")
    
    # Ensure ThreadJob module is available
    if (-not (Get-Module -ListAvailable -Name ThreadJob)) {
        Write-Warning "ThreadJob module not available - some tests may fail"
    }
}

AfterAll {
    # Clean up
    Remove-Variable -Name IsTestRun -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
    Remove-Item env:PESTER_TEST_RUN -ErrorAction SilentlyContinue
    Remove-Item env:LOXONE_TEST_MODE -ErrorAction SilentlyContinue
    Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
    
    if (Test-Path $script:TestDir) {
        Remove-Item $script:TestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Parallel Workflow Integration" -Tag 'Integration', 'ParallelWorkflow' {
    
    Context "End-to-End Workflow Execution" {
        
        BeforeEach {
            # Clear any existing parallel mode flag
            Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
            
            # Create test files
            $script:TestConfigZip = Join-Path $script:TestDir "test_config.zip"
            $script:TestAppMsi = Join-Path $script:TestDir "test_app.msi"
            
            # Create mock files
            "Mock config content" | Out-File $script:TestConfigZip -Encoding UTF8
            "Mock app content" | Out-File $script:TestAppMsi -Encoding UTF8
        }
        
        AfterEach {
            Remove-Item env:LOXONE_PARALLEL_MODE -ErrorAction SilentlyContinue
        }
        
        It "Completes workflow with no updates needed" {
            # Empty workflow
            $workflowDef = @{
                ConfigUpdate = $null
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            $result | Should -Not -BeNullOrEmpty
            $result.Success | Should -Be $true
            $result.TotalDuration | Should -BeGreaterOrEqual 0
            
            # Verify no workers created unnecessary work
            # Note: Collections are hashtables, check Keys.Count for actual entries
            if ($result.Downloads) {
                $result.Downloads.Keys.Count | Should -Be 0
            }
            if ($result.Installations) {
                $result.Installations.Keys.Count | Should -Be 0
            }
            if ($result.Miniservers) {
                $result.Miniservers.Keys.Count | Should -Be 0
            }
        }
        
        It "Coordinates download and install workers for Config update" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # In test mode, the workflow should use mock functions
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.loxone.com/config.zip"
                    ExpectedCRC32 = "12345678"
                    FileSize = 1000
                    TargetVersion = "14.0.0.0"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef -MaxConcurrency 2
            
            # Allow time for workers to process
            Start-Sleep -Milliseconds 500
            
            $result | Should -Not -BeNullOrEmpty
            $result.Success | Should -Be $true
            
            # In test mode, verify that results contain expected structure
            $result.Downloads | Should -Not -BeNullOrEmpty
            $result.Downloads['Config_Download'] | Should -Not -BeNullOrEmpty
            $result.Downloads['Config_Download'].Success | Should -Be $true
            
            $result.Installations | Should -Not -BeNullOrEmpty
            $result.Installations['Config_Install'] | Should -Not -BeNullOrEmpty
            $result.Installations['Config_Install'].Success | Should -Be $true
        }
        
        It "Handles multiple concurrent downloads" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.loxone.com/config.zip"
                    ExpectedCRC32 = "12345678"
                    FileSize = 1000
                    TargetVersion = "14.0.0.0"
                }
                AppUpdate = @{
                    Url = "http://test.loxone.com/app.msi"
                    ExpectedCRC32 = "87654321"
                    FileSize = 2000
                    TargetVersion = "1.0.0.0"
                }
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            $startTime = Get-Date
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef -MaxConcurrency 2
            $duration = (Get-Date) - $startTime
            
            # Allow time for workers
            Start-Sleep -Milliseconds 500
            
            $result.Success | Should -Be $true
            $result.Downloads.Keys.Count | Should -Be 2
            
            # Both downloads should complete in test mode
            $result.Downloads['Config_Download'] | Should -Not -BeNullOrEmpty
            $result.Downloads['Config_Download'].Success | Should -Be $true
            $result.Downloads['App_Download'] | Should -Not -BeNullOrEmpty
            $result.Downloads['App_Download'].Success | Should -Be $true
        }
    }
    
    Context "Worker Error Handling" {
        
        It "Handles download worker failures gracefully" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # This test can't work reliably with ThreadJobs because mocks don't cross thread boundaries
            # The ParallelWorkflow module needs to be refactored to support dependency injection
            # or use a different testing approach that doesn't rely on mocking across threads
        }
        
        It "Handles install worker failures gracefully" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # This test can't work reliably with ThreadJobs because mocks don't cross thread boundaries
            # The ParallelWorkflow module needs to be refactored to support dependency injection
            # or use a different testing approach that doesn't rely on mocking across threads
        }
    }
    
    Context "Miniserver Worker Coordination" {
        
        It "Processes multiple miniservers concurrently" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # This test can't work reliably with ThreadJobs because mocks don't cross thread boundaries
            # The test would need to be rewritten to use a different approach
        }
        
        It "Respects MaxMSConcurrency limit" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # This test can't work reliably with ThreadJobs because mocks don't cross thread boundaries
            # The concurrency limit is enforced by the ThreadJob throttle limit in the actual implementation
        }
    }
    
    Context "Progress Aggregation" {
        
        It "Aggregates progress from all workers" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # This test would require access to progress state
            # For now, just verify the workflow completes with progress tracking
            
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.loxone.com/config.zip"
                    ExpectedCRC32 = "12345678"
                    FileSize = 1000
                    TargetVersion = "14.0.0.0"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            # Mock download with progress updates
            Mock Invoke-LoxoneDownload -ModuleName LoxoneUtils.Network {
                param($Url, $DestinationPath)
                "Mock content" | Out-File $DestinationPath -Encoding UTF8
                return @{
                    Success = $true
                    CalculatedCRC32 = "MOCKCRC32"
                    ActualFilesize = 1000
                    LocalPath = $DestinationPath
                }
            }
            
            Mock Invoke-ZipFileExtraction -ModuleName LoxoneUtils.Installation {
                param($ZipPath, $DestinationPath)
                New-Item -ItemType File -Path (Join-Path $DestinationPath "setup.exe") -Force | Out-Null
                return @{ Success = $true }
            }
            
            Mock Start-LoxoneUpdateInstaller -ModuleName LoxoneUtils.Installation {
                return @{ Success = $true; ExitCode = 0 }
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            # Allow time for progress updates
            Start-Sleep -Milliseconds 300
            
            $result.Success | Should -Be $true
            $result.TotalDuration | Should -BeGreaterThan 0
        }
    }
    
    # State persistence removed - existing download/install functions handle resume
}

Describe "Worker Communication" -Tag 'Integration', 'ParallelWorkflow' {
    
    Context "Queue Operations" {
        
        It "Download worker enqueues install tasks" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # Test that download completion triggers install queue
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.loxone.com/config.zip"
                    ExpectedCRC32 = "12345678"
                    FileSize = 1000
                    TargetVersion = "14.0.0.0"
                }
                AppUpdate = $null
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef
            
            # Allow time for queue processing
            Start-Sleep -Milliseconds 500
            
            # Both download and install should complete in test mode
            $result.Downloads['Config_Download'] | Should -Not -BeNullOrEmpty
            $result.Installations['Config_Install'] | Should -Not -BeNullOrEmpty
            
            # Verify install was triggered after download
            $result.Installations['Config_Install'].Success | Should -Be $true
        }
        
        It "Handles concurrent queue operations safely" -Skip:($true) {  # Skip: Requires real network access in ThreadJobs
            # Test thread-safe queue operations with multiple items
            $workflowDef = @{
                ConfigUpdate = @{
                    Url = "http://test.loxone.com/config.zip"
                    ExpectedCRC32 = "12345678"
                    FileSize = 1000
                    TargetVersion = "14.0.0.0"
                }
                AppUpdate = @{
                    Url = "http://test.loxone.com/app.msi"
                    ExpectedCRC32 = "87654321"
                    FileSize = 2000
                    TargetVersion = "1.0.0.0"
                }
                MiniserverUpdates = @()
                ScriptSaveFolder = $script:TestDir
            }
            
            $result = Start-ParallelWorkflow -WorkflowDefinition $workflowDef -MaxConcurrency 4
            
            # Allow time for all operations
            Start-Sleep -Milliseconds 800
            
            $result.Success | Should -Be $true
            
            # All operations should complete
            $result.Downloads.Keys.Count | Should -Be 2
            $result.Installations.Keys.Count | Should -Be 2
            
            # No operations should be lost due to race conditions
            $result.Downloads['Config_Download'].Success | Should -Be $true
            $result.Downloads['App_Download'].Success | Should -Be $true
            $result.Installations['Config_Install'].Success | Should -Be $true
            $result.Installations['App_Install'].Success | Should -Be $true
        }
    }
}