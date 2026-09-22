# Mocks for RunAsUser module to prevent elevated privilege operations during tests

# Prevent the RunAsUser type from being compiled (which requires WTSQueryUserToken)
if (-not $env:PESTER_TEST_RUN) {
    $env:PESTER_TEST_RUN = "1"
}

# Create a fake type to prevent compilation
if (-not ([System.Management.Automation.PSTypeName]'RunAsUser.ProcessExtensions').Type) {
    Add-Type -TypeDefinition @"
    namespace RunAsUser {
        public class ProcessExtensions {
            public static object StartProcessAsCurrentUser(
                string applicationPath,
                string commandLine,
                string workingDirectory,
                bool hidden)
            {
                // Mock implementation - just return success
                return new {
                    Success = true,
                    ProcessId = 12345,
                    Message = "MOCK: Process started"
                };
            }
        }
    }
"@ -ErrorAction SilentlyContinue
}

# Mock the function if it exists
if (Get-Command Start-ProcessAsCurrentUser -ErrorAction SilentlyContinue) {
    Mock Start-ProcessAsCurrentUser {
        param($Application, $CommandLine, $WorkingDirectory, $Hidden)
        
        Write-Verbose "[MOCK] Start-ProcessAsCurrentUser called"
        Write-Verbose "[MOCK] Application: $Application"
        Write-Verbose "[MOCK] CommandLine: $CommandLine"
        
        return @{
            Success = $true
            ProcessId = Get-Random -Minimum 1000 -Maximum 9999
            Message = "MOCK: Process started successfully"
        }
    }
}

# Create global functions that can be mocked later
if (-not (Get-Command Test-IsRunningAsSystem -ErrorAction SilentlyContinue)) {
    function global:Test-IsRunningAsSystem {
        Write-Verbose "[MOCK-STUB] Test-IsRunningAsSystem returning false"
        return $false
    }
}

if (-not (Get-Command Test-IsAdministrator -ErrorAction SilentlyContinue)) {
    function global:Test-IsAdministrator {
        Write-Verbose "[MOCK-STUB] Test-IsAdministrator returning false"
        return $false
    }
}

Write-Host "RunAsUser mocks loaded - no elevated operations will be attempted" -ForegroundColor Green