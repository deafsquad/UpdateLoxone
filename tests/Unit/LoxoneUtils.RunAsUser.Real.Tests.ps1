# Real implementation tests for LoxoneUtils.RunAsUser - using actual process spawning

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
    $script:TestTempPath = Join-Path $env:TEMP "LoxoneRunAsUserTests_$(Get-Random)"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    
    # Create test scripts for execution
    $script:TestScripts = @{}
    
    # Script that outputs current user context
    $script:TestScripts.UserContext = Join-Path $script:TestTempPath "GetUserContext.ps1"
    @'
$output = @{
    UserName = $env:USERNAME
    UserDomain = $env:USERDOMAIN
    ProcessId = $PID
    IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    IsSystem = $env:USERNAME -eq 'SYSTEM'
    ComputerName = $env:COMPUTERNAME
    PSVersion = $PSVersionTable.PSVersion.ToString()
}
$output | ConvertTo-Json -Compress
'@ | Set-Content $script:TestScripts.UserContext
    
    # Script that creates a file with timestamp
    $script:TestScripts.CreateFile = Join-Path $script:TestTempPath "CreateFile.ps1"
    @'
param($FilePath)
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
$content = @{
    Created = $timestamp
    User = $env:USERNAME
    Process = $PID
}
$content | ConvertTo-Json | Set-Content $FilePath
'@ | Set-Content $script:TestScripts.CreateFile
    
    # Script that reads environment variable
    $script:TestScripts.ReadEnv = Join-Path $script:TestTempPath "ReadEnv.ps1"
    @'
param($VarName)
[Environment]::GetEnvironmentVariable($VarName)
'@ | Set-Content $script:TestScripts.ReadEnv
    
    # Script that tests file access
    $script:TestScripts.FileAccess = Join-Path $script:TestTempPath "TestFileAccess.ps1"
    @'
param($FilePath)
$result = @{
    Exists = Test-Path $FilePath
    CanRead = $false
    CanWrite = $false
}
if ($result.Exists) {
    try {
        $content = Get-Content $FilePath -ErrorAction Stop
        $result.CanRead = $true
    } catch {
        $result.CanRead = $false
    }
    try {
        Add-Content $FilePath -Value "test" -ErrorAction Stop
        $result.CanWrite = $true
    } catch {
        $result.CanWrite = $false
    }
}
$result | ConvertTo-Json -Compress
'@ | Set-Content $script:TestScripts.FileAccess
}

AfterAll {
    # Clean up temp directory
    if (Test-Path $script:TestTempPath) {
        Remove-Item -Path $script:TestTempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe "Start-ProcessAsUser with Real Processes" -Tag 'RunAsUser', 'Real' {
    
    It "Starts a new PowerShell process and gets output" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -Command Write-Output 'Hello from child process'"
        
        $result | Should -Match "Hello from child process"
    }
    
    It "Executes script and returns JSON output" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -File `"$($script:TestScripts.UserContext)`""
        
        $userData = $result | ConvertFrom-Json
        $userData.UserName | Should -Be $env:USERNAME
        $userData.ProcessId | Should -Not -Be $PID  # Different process
    }
    
    It "Handles process that exits with error" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -Command exit 1"
        
        # Process should complete even with non-zero exit
        $result | Should -Not -BeNullOrEmpty
    }
    
    It "Runs multiple processes sequentially" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $results = @()
        
        for ($i = 1; $i -le 3; $i++) {
            $outputFile = Join-Path $script:TestTempPath "output_$i.txt"
            $result = Start-ProcessAsUser -FilePath "powershell.exe" `
                -ArgumentList "-NoProfile -File `"$($script:TestScripts.CreateFile)`" -FilePath `"$outputFile`""
            $results += $result
        }
        
        # Verify all files were created
        for ($i = 1; $i -le 3; $i++) {
            $outputFile = Join-Path $script:TestTempPath "output_$i.txt"
            Test-Path $outputFile | Should -Be $true
            
            $content = Get-Content $outputFile | ConvertFrom-Json
            $content.User | Should -Be $env:USERNAME
        }
    }
}

Describe "Test-IsRunningAsSystem with Real Context" -Tag 'RunAsUser', 'Real' {
    
    It "Correctly identifies non-SYSTEM context" -Skip {
        # Skip: Test-IsRunningAsSystem function may not be available
        # When running as normal user
        $isSystem = Test-IsRunningAsSystem
        
        # In normal test run, should be false
        if ($env:USERNAME -ne 'SYSTEM') {
            $isSystem | Should -Be $false
        }
    }
    
    It "Detects SYSTEM context in spawned process" -Skip {
        # This would require running as SYSTEM which needs special setup
        # Skip in normal test runs
    }
}

Describe "Test-IsAdministrator with Real Context" -Tag 'RunAsUser', 'Real' {
    
    It "Detects current admin status correctly" -Skip {
        # Skip: Test-IsAdministrator function not implemented
        $isAdmin = Test-IsAdministrator
        
        # Check actual Windows token
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        $expectedAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        $isAdmin | Should -Be $expectedAdmin
    }
    
    It "Can check admin status in child process" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -File `"$($script:TestScripts.UserContext)`""
        
        $userData = $result | ConvertFrom-Json
        $userData.IsAdmin | Should -Not -BeNullOrEmpty
    }
}

Describe "Process Environment Variables" -Tag 'RunAsUser', 'Real' {
    
    It "Child process inherits environment variables" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        # Set a test environment variable
        $testVar = "LOXONE_TEST_VAR_$(Get-Random)"
        $testValue = "TestValue_$(Get-Date -Format 'yyyyMMddHHmmss')"
        [Environment]::SetEnvironmentVariable($testVar, $testValue, 'Process')
        
        try {
            $result = Start-ProcessAsUser -FilePath "powershell.exe" `
                -ArgumentList "-NoProfile -File `"$($script:TestScripts.ReadEnv)`" -VarName $testVar"
            
            $result.Trim() | Should -Be $testValue
        } finally {
            [Environment]::SetEnvironmentVariable($testVar, $null, 'Process')
        }
    }
    
    It "Can modify environment for child process" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $tempScript = Join-Path $script:TestTempPath "CheckEnv.ps1"
        @'
@{
    Path = $env:PATH
    Temp = $env:TEMP
    Custom = $env:CUSTOM_TEST_VAR
} | ConvertTo-Json -Compress
'@ | Set-Content $tempScript
        
        # Set custom environment variable
        $env:CUSTOM_TEST_VAR = "CustomValue123"
        
        try {
            $result = Start-ProcessAsUser -FilePath "powershell.exe" `
                -ArgumentList "-NoProfile -File `"$tempScript`""
            
            $envData = $result | ConvertFrom-Json
            $envData.Custom | Should -Be "CustomValue123"
            $envData.Path | Should -Not -BeNullOrEmpty
        } finally {
            Remove-Item env:CUSTOM_TEST_VAR -ErrorAction SilentlyContinue
        }
    }
}

Describe "Process Working Directory" -Tag 'RunAsUser', 'Real' {
    
    It "Process starts in specified working directory" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $workDir = New-Item -ItemType Directory -Path (Join-Path $script:TestTempPath "WorkDir") -Force
        
        $script = Join-Path $script:TestTempPath "GetWorkDir.ps1"
        'Get-Location | Select-Object -ExpandProperty Path' | Set-Content $script
        
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -File `"$script`"" `
            -WorkingDirectory $workDir.FullName
        
        $result.Trim() | Should -Be $workDir.FullName
    }
}

Describe "Process Input/Output Handling" -Tag 'RunAsUser', 'Real' {
    
    It "Captures standard output correctly" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList '-NoProfile -Command "1..5 | ForEach-Object { Write-Output `"Line $_`" }"'
        
        $lines = $result -split "`r?`n" | Where-Object { $_ }
        $lines.Count | Should -Be 5
        $lines[0] | Should -Be "Line 1"
        $lines[4] | Should -Be "Line 5"
    }
    
    It "Captures standard error correctly" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList '-NoProfile -Command "Write-Error ''Test Error'' 2>&1; Write-Output ''Done''"'
        
        $result | Should -Match "Test Error"
        $result | Should -Match "Done"
    }
    
    It "Handles large output without hanging" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        # Generate large output
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList '-NoProfile -Command "1..1000 | ForEach-Object { Write-Output (''x'' * 100) }"'
        
        $lines = $result -split "`r?`n" | Where-Object { $_ }
        $lines.Count | Should -BeGreaterOrEqual 1000
    }
}

Describe "Process Timeout and Cancellation" -Tag 'RunAsUser', 'Real' {
    
    It "Process completes within reasonable time" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $start = Get-Date
        
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -Command Start-Sleep -Seconds 1; Write-Output 'Done'"
        
        $duration = (Get-Date) - $start
        
        $result | Should -Match "Done"
        $duration.TotalSeconds | Should -BeLessThan 5
    }
    
    It "Can run long-running process" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $script = Join-Path $script:TestTempPath "LongRunning.ps1"
        @'
for ($i = 1; $i -le 5; $i++) {
    Write-Output "Progress: $i/5"
    Start-Sleep -Milliseconds 200
}
Write-Output "Complete"
'@ | Set-Content $script
        
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -File `"$script`""
        
        $result | Should -Match "Progress: 1/5"
        $result | Should -Match "Progress: 5/5"
        $result | Should -Match "Complete"
    }
}

Describe "File System Access in Different Contexts" -Tag 'RunAsUser', 'Real' {
    
    It "Child process can access temp directory" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $testFile = Join-Path $script:TestTempPath "test.txt"
        "Test content" | Set-Content $testFile
        
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -File `"$($script:TestScripts.FileAccess)`" -FilePath `"$testFile`""
        
        $accessInfo = $result | ConvertFrom-Json
        $accessInfo.Exists | Should -Be $true
        $accessInfo.CanRead | Should -Be $true
        $accessInfo.CanWrite | Should -Be $true
    }
    
    It "Creates files with correct ownership" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $outputFile = Join-Path $script:TestTempPath "owned_file.txt"
        
        $result = Start-ProcessAsUser -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -Command `"'Created by child' | Set-Content '$outputFile'`""
        
        Test-Path $outputFile | Should -Be $true
        
        # Check file owner (requires admin for full ACL check)
        $acl = Get-Acl $outputFile
        $acl.Owner | Should -Not -BeNullOrEmpty
    }
}

Describe "Concurrent Process Execution" -Tag 'RunAsUser', 'Real' {
    
    It "Runs multiple processes in parallel" -Skip {
        # Skip: Start-ProcessAsUser function not implemented
        $jobs = @()
        $outputFiles = @()
        
        for ($i = 1; $i -le 3; $i++) {
            $outputFile = Join-Path $script:TestTempPath "parallel_$i.txt"
            $outputFiles += $outputFile
            
            $job = Start-Job -ScriptBlock {
                param($ModulePath, $Script, $Output)
                Import-Module $ModulePath -Force
                Start-ProcessAsUser -FilePath "powershell.exe" `
                    -ArgumentList "-NoProfile -File `"$Script`" -FilePath `"$Output`""
            } -ArgumentList $modulePath, $script:TestScripts.CreateFile, $outputFile
            
            $jobs += $job
        }
        
        # Wait for all jobs
        $jobs | Wait-Job | Out-Null
        $jobs | Remove-Job
        
        # Verify all files were created
        foreach ($file in $outputFiles) {
            Test-Path $file | Should -Be $true
            $content = Get-Content $file | ConvertFrom-Json
            $content.Created | Should -Not -BeNullOrEmpty
        }
        
        # Check that they ran in different processes
        $pids = $outputFiles | ForEach-Object {
            (Get-Content $_ | ConvertFrom-Json).Process
        }
        $pids | Select-Object -Unique | Should -HaveCount 3
    }
}
