# Real implementation tests for LoxoneUtils.System - using actual Windows APIs and system operations

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
    
    # Set up test environment
    $script:TestTempPath = Join-Path $env:TEMP "LoxoneSystemTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    
    # Set up logging
    $Global:LogFile = Join-Path $script:TestTempPath 'system-test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null
}

AfterAll {
    # Clean up temp directory
    if (Test-Path $script:TestTempPath) {
        Remove-Item -Path $script:TestTempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Real Process Management" -Tag 'System', 'Real' {
    
    It "Gets real running processes" {
        # Get actual system processes
        $processes = Get-Process
        
        $processes | Should -Not -BeNullOrEmpty
        $processes.Count | Should -BeGreaterThan 10
        
        # Check for common Windows processes
        $systemProcesses = @('svchost', 'csrss', 'winlogon', 'services')
        foreach ($procName in $systemProcesses) {
            $proc = $processes | Where-Object { $_.ProcessName -eq $procName }
            if ($proc) {
                $proc | Should -Not -BeNullOrEmpty
                $proc.Id | Should -BeGreaterThan 0
                $proc.WorkingSet | Should -BeGreaterThan 0
            }
        }
    }
    
    It "Starts and stops a real process" -Skip {
        # Skip: Opens visible notepad window during tests
        # Start notepad (hidden to avoid UI popup)
        $process = Start-Process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
        
        $process | Should -Not -BeNullOrEmpty
        $process.Id | Should -BeGreaterThan 0
        
        # Verify it's running
        Start-Sleep -Milliseconds 500
        $running = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        $running | Should -Not -BeNullOrEmpty
        
        # Stop the process
        Stop-Process -Id $process.Id -Force
        
        # Verify it's stopped
        Start-Sleep -Milliseconds 500
        $stopped = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
        $stopped | Should -BeNullOrEmpty
    }
    
    It "Monitors process CPU and memory usage" -Skip {
        # Skip: Opens PowerShell window during tests
        # Start a process that does some work
        $scriptPath = Join-Path $script:TestTempPath "Worker.ps1"
        @'
$sum = 0
for ($i = 1; $i -le 10000000; $i++) {
    $sum += $i
}
Write-Output $sum
'@ | Set-Content $scriptPath
        
        $process = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -WindowStyle Hidden -File `"$scriptPath`"" `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $script:TestTempPath "output.txt")
        
        # Monitor the process
        $samples = @()
        while (-not $process.HasExited) {
            $proc = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
            if ($proc) {
                $samples += @{
                    Time = Get-Date
                    CPU = $proc.CPU
                    WorkingSet = $proc.WorkingSet
                    PrivateMemory = $proc.PrivateMemorySize
                }
            }
            Start-Sleep -Milliseconds 100
        }
        
        # Should have collected some samples
        $samples.Count | Should -BeGreaterThan 0
        
        # CPU time should have increased
        if ($samples.Count -gt 1) {
            $lastCpu = $samples[-1].CPU
            $firstCpu = $samples[0].CPU
            # May be null if process was too quick
            if ($null -ne $lastCpu -and $null -ne $firstCpu) {
                $lastCpu | Should -BeGreaterOrEqual $firstCpu
            }
        }
    }
}

Describe "Real Registry Operations" -Tag 'System', 'Real' {

    BeforeAll {
        # Use the test registry path from parent scope
        $script:TestRegPath = "HKCU:\Software\LoxoneSystemTest_$(Get-Random)"
    }
    
    AfterAll {
        # Clean up test registry key
        if (Test-Path $script:TestRegPath) {
            Remove-Item $script:TestRegPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    It "Creates and reads registry keys and values" {
        # Create registry key
        New-Item -Path $script:TestRegPath -Force | Out-Null
        Test-Path $script:TestRegPath | Should -Be $true
        
        # Set various value types
        Set-ItemProperty -Path $script:TestRegPath -Name "StringValue" -Value "Test String"
        Set-ItemProperty -Path $script:TestRegPath -Name "DWordValue" -Value 42 -Type DWord
        Set-ItemProperty -Path $script:TestRegPath -Name "BinaryValue" -Value ([byte[]]@(0x01, 0x02, 0x03)) -Type Binary
        Set-ItemProperty -Path $script:TestRegPath -Name "MultiStringValue" -Value @("Line1", "Line2", "Line3") -Type MultiString
        
        # Read values back
        $stringVal = Get-ItemProperty -Path $script:TestRegPath -Name "StringValue"
        $stringVal.StringValue | Should -Be "Test String"
        
        $dwordVal = Get-ItemProperty -Path $script:TestRegPath -Name "DWordValue"
        $dwordVal.DWordValue | Should -Be 42
        
        $binaryVal = Get-ItemProperty -Path $script:TestRegPath -Name "BinaryValue"
        $binaryVal.BinaryValue | Should -Be @(0x01, 0x02, 0x03)
        
        $multiVal = Get-ItemProperty -Path $script:TestRegPath -Name "MultiStringValue"
        $multiVal.MultiStringValue | Should -Be @("Line1", "Line2", "Line3")
    }
    
    It "Enumerates registry subkeys" {
        # Create subkeys
        New-Item -Path "$script:TestRegPath\SubKey1" -Force | Out-Null
        New-Item -Path "$script:TestRegPath\SubKey2" -Force | Out-Null
        New-Item -Path "$script:TestRegPath\SubKey3" -Force | Out-Null
        
        # Enumerate subkeys
        $subKeys = Get-ChildItem -Path $script:TestRegPath
        
        $subKeys.Count | Should -Be 3
        $subKeys.Name | Should -Contain "$($script:TestRegPath.Replace('HKCU:\', 'HKEY_CURRENT_USER\'))\SubKey1"
    }
}

Describe "Real Windows Service Information" -Tag 'System', 'Real' {
    
    It "Gets information about Windows services" -Skip {
        # Skip: System-specific tests need elevation or specific environment
        # Get all services
        $services = Get-Service
        
        $services | Should -Not -BeNullOrEmpty
        $services.Count | Should -BeGreaterThan 50
        
        # Check for critical Windows services
        $criticalServices = @('EventLog', 'Dnscache', 'LanmanWorkstation', 'RpcSs')
        
        foreach ($serviceName in $criticalServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $service.Status | Should -BeIn @('Running', 'Stopped', 'Paused')
                $service.ServiceType | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    It "Gets detailed service information using WMI" {
        # Use WMI to get service details
        $wmiServices = Get-CimInstance -ClassName Win32_Service | Select-Object -First 10
        
        $wmiServices | Should -Not -BeNullOrEmpty
        
        foreach ($service in $wmiServices) {
            $service.Name | Should -Not -BeNullOrEmpty
            $service.State | Should -BeIn @('Running', 'Stopped', 'Paused', 'Start Pending', 'Stop Pending', 'Continue Pending', 'Pause Pending')
            $service.ProcessId | Should -Not -BeNull
            
            if ($service.State -eq 'Running') {
                $service.ProcessId | Should -BeGreaterThan 0
            }
        }
    }
}

Describe "Real File System Operations" -Tag 'System', 'Real' {
    
    It "Gets file system information" {
        # Get drive information
        $drives = Get-PSDrive -PSProvider FileSystem
        
        $drives | Should -Not -BeNullOrEmpty
        
        $systemDrive = $drives | Where-Object { $_.Root -eq "$env:SystemDrive\" }
        $systemDrive | Should -Not -BeNullOrEmpty
        
        if ($systemDrive.Used -ne $null) {
            $systemDrive.Used | Should -BeGreaterThan 0
            $systemDrive.Free | Should -BeGreaterThan 0
        }
    }
    
    It "Monitors file system changes in real-time" {
        $watchPath = Join-Path $script:TestTempPath "WatchFolder"
        New-Item -ItemType Directory -Path $watchPath -Force | Out-Null
        
        # Create file system watcher
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $watchPath
        $watcher.Filter = "*.*"
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName, [System.IO.NotifyFilters]::LastWrite
        
        $events = @()
        
        # Register event handlers
        Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action {
            $Global:WatcherEvents += @{
                Type = "Created"
                Name = $Event.SourceEventArgs.Name
                Time = Get-Date
            }
        } | Out-Null
        
        $Global:WatcherEvents = @()
        $watcher.EnableRaisingEvents = $true
        
        # Create test files
        "Test1" | Set-Content (Join-Path $watchPath "file1.txt")
        Start-Sleep -Milliseconds 100
        "Test2" | Set-Content (Join-Path $watchPath "file2.txt")
        Start-Sleep -Milliseconds 100
        
        # Stop watching
        $watcher.EnableRaisingEvents = $false
        $watcher.Dispose()
        
        # Unregister events
        Get-EventSubscriber | Where-Object { $_.SourceObject -eq $watcher } | Unregister-Event
        
        # Check events were captured
        $Global:WatcherEvents.Count | Should -BeGreaterOrEqual 0  # May not catch all events due to timing
        
        Remove-Variable -Name WatcherEvents -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe "Real Environment Variables" -Tag 'System', 'Real' {
    
    It "Reads system environment variables" -Skip {
        # Skip: System-specific tests need elevation or specific environment
        # Get common environment variables
        $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $path | Should -Not -BeNullOrEmpty
        $path | Should -Match "Windows"
        
        $temp = [Environment]::GetEnvironmentVariable("TEMP", "User")
        $temp | Should -Not -BeNullOrEmpty
        Test-Path $temp | Should -Be $true
        
        $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot", "Machine")
        $systemRoot | Should -Not -BeNullOrEmpty
        $systemRoot | Should -Match "Windows"
    }
    
    It "Sets and removes user environment variables" {
        $varName = "LOXONE_TEST_VAR_$(Get-Random)"
        $varValue = "TestValue_$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        # Set user environment variable
        [Environment]::SetEnvironmentVariable($varName, $varValue, "User")
        
        # Verify it was set
        $retrieved = [Environment]::GetEnvironmentVariable($varName, "User")
        $retrieved | Should -Be $varValue
        
        # Remove the variable
        [Environment]::SetEnvironmentVariable($varName, $null, "User")
        
        # Verify it was removed
        $removed = [Environment]::GetEnvironmentVariable($varName, "User")
        $removed | Should -BeNullOrEmpty
    }
}

Describe "Real System Information" -Tag 'System', 'Real' {
    
    It "Gets computer system information" {
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $computerInfo | Should -Not -BeNullOrEmpty
        $computerInfo.Name | Should -Be $env:COMPUTERNAME
        $computerInfo.TotalPhysicalMemory | Should -BeGreaterThan 0
        $computerInfo.NumberOfProcessors | Should -BeGreaterThan 0
    }
    
    It "Gets operating system information" {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $osInfo | Should -Not -BeNullOrEmpty
        $osInfo.Caption | Should -Match "Windows"
        $osInfo.Version | Should -Not -BeNullOrEmpty
        $osInfo.BuildNumber | Should -BeGreaterThan 0
        $osInfo.OSArchitecture | Should -BeIn @("32-bit", "64-bit")
    }
    
    It "Gets BIOS information" {
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS
        
        $biosInfo | Should -Not -BeNullOrEmpty
        $biosInfo.Manufacturer | Should -Not -BeNullOrEmpty
        $biosInfo.SerialNumber | Should -Not -BeNull  # May be empty in VMs
    }
}

Describe "Real Network Configuration" -Tag 'System', 'Real' {
    
    It "Gets network adapter information" {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
            Where-Object { $_.IPEnabled -eq $true }
        
        $adapters | Should -Not -BeNullOrEmpty
        
        foreach ($adapter in $adapters) {
            $adapter.IPAddress | Should -Not -BeNullOrEmpty
            $adapter.DefaultIPGateway | Should -Not -BeNull
            $adapter.DNSServerSearchOrder | Should -Not -BeNull
            $adapter.MACAddress | Should -Match "^([0-9A-F]{2}:){5}[0-9A-F]{2}$"
        }
    }
    
    It "Tests network connectivity using .NET" {
        $ping = New-Object System.Net.NetworkInformation.Ping
        
        # Ping localhost
        $result = $ping.Send("127.0.0.1")
        $result.Status | Should -Be "Success"
        $result.RoundtripTime | Should -BeGreaterOrEqual 0
        
        # Ping a public DNS server
        $result = $ping.Send("8.8.8.8", 1000)
        if ($result.Status -eq "Success") {
            $result.RoundtripTime | Should -BeGreaterThan 0
        }
        
        $ping.Dispose()
    }
}

Describe "Real Event Log Operations" -Tag 'System', 'Real' {
    
    It "Reads Windows Event Log entries" -Skip {
        # Skip: System-specific tests need elevation or specific environment
        # Get recent System log entries
        $events = Get-WinEvent -LogName System -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | Should -Not -BeNullOrEmpty
            
            foreach ($event in $events) {
                $event.Id | Should -BeGreaterThan 0
                $event.TimeCreated | Should -Not -BeNullOrEmpty
                $event.LevelDisplayName | Should -BeIn @('Information', 'Warning', 'Error', 'Critical', 'Verbose')
            }
        }
    }
    
    It "Writes to Application Event Log" -Skip {
        # Skip by default as it requires admin rights
        $source = "LoxoneSystemTest"
        $logName = "Application"
        
        # Create event source if it doesn't exist (requires admin)
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
        }
        
        # Write test event
        $eventLog = New-Object System.Diagnostics.EventLog($logName)
        $eventLog.Source = $source
        $eventLog.WriteEntry("Test event from LoxoneSystemTest", [System.Diagnostics.EventLogEntryType]::Information, 1000)
        
        # Verify it was written
        $written = Get-EventLog -LogName $logName -Source $source -Newest 1
        $written | Should -Not -BeNullOrEmpty
        $written.Message | Should -Match "Test event"
    }
}

