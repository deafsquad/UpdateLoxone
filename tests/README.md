# UpdateLoxone Test Suite

Comprehensive PowerShell Pester tests for the UpdateLoxone project.

## Quick Start

```powershell
# Run unit tests (fast, default)
.\run-tests.ps1

# Run all tests
.\run-tests.ps1 -TestType All

# Get help
.\run-tests.ps1 -?
```

## Test Architecture

### Unified Test Runner
All test functionality is consolidated into `run-tests.ps1`:
- Single source of truth for all testing
- Rich parameter support for various scenarios
- Integrated cleanup and result management

### Directory Structure
```
tests/
├── run-tests.ps1          # Main test runner
│
├── Unit/                  # Unit tests (no external dependencies)
│   └── LoxoneUtils.*.Tests.ps1
│
├── Integration/           # Integration tests (network/external deps)
│   └── LoxoneUtils.*.Tests.ps1
│
├── Helpers/              # Internal helper scripts
│   └── invoke-system-tests.ps1
│
├── Fixtures/             # Test data and mocks
│   ├── TestData/
│   └── Mocks/
│
├── temp/                 # Temporary test files (auto-cleaned)
│
└── TestResults/          # All test results
    ├── LastRun/          # Most recent test results
    └── Archive/          # Historical results (7-day retention)
```

## Test Categories

### Unit Tests (Default)
- Fast execution, no external dependencies
- Mock all external calls
- Located in `Unit/` directory
- Run with: `.\run-tests.ps1`

### Integration Tests
- Require network/external resources
- Longer execution time
- Located in `Integration/` directory
- Run with: `.\run-tests.ps1 -TestType Integration`

### System Tests
- Require administrator privileges
- Test SYSTEM context functionality
- Use PsExec for privilege elevation
- Run with: `.\run-tests.ps1 -TestType System`

## Common Usage Examples

```powershell
# Quick unit test run
.\run-tests.ps1

# Full test suite
.\run-tests.ps1 -TestType All

# Specific module
.\run-tests.ps1 -Filter "Logging"

# With detailed output
.\run-tests.ps1 -Detailed

# Debug mode
.\run-tests.ps1 -DebugMode

# Generate coverage report
.\run-tests.ps1 -GenerateCoverage

# CI/CD mode (no prompts, minimal output)
.\run-tests.ps1 -CI

# Skip SYSTEM tests (which require admin)
.\run-tests.ps1 -SkipSystemTests

# Live progress notifications
.\run-tests.ps1 -LiveProgress
```

## Test Results

All test results are organized in the `TestResults/` directory:

### LastRun/
- Always contains the most recent test results
- Cleared before each new test run
- Contains logs, XML results, and JSON summaries

### Archive/
- Timestamped folders for important test runs
- Automatically created for failed tests or non-console output
- 7-day retention with automatic cleanup

## Known Issues and Solutions

### Pester Tag Filtering Behavior
When using Pester's `ExcludeTag` feature, it applies aggressive filtering at the file/container level. If ANY `Describe` block in a test file has a tag that matches the `ExcludeTag` list, Pester may skip the ENTIRE file. This is why Unit tests don't use ExcludeTag filtering.

### Test Isolation
The test runner creates isolated temp folders (`temp\TestRun_TIMESTAMP`) and sets `$env:UPDATELOXONE_TEST_TEMP` to the isolated path. Tests should use this environment variable or Pester's `$TestDrive` for temporary files instead of hard-coded paths.

## Best Practices

1. **Before Committing**: Run `.\run-tests.ps1` to ensure unit tests pass
2. **Before Pull Requests**: Run `.\run-tests.ps1 -TestType All`
3. **Debugging Failures**: Use `-DebugMode -Filter "TestName"`
4. **Clean Environment**: Run with `-CleanupTestFiles` periodically
5. **Module Development**: Update tests when changing module functions

## Troubleshooting

### Common Issues

1. **Pester Not Found**
   ```powershell
   Install-Module -Name Pester -Force -SkipPublisherCheck
   ```

2. **Execution Policy Errors**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Permission Denied**
   - System tests require administrator privileges
   - Use `-SkipSystemTests` or run as admin

4. **Test Timeouts**
   - Increase timeout: `-Timeout 300`
   - Check for network connectivity issues
   - Use `-TestType Unit` to skip integration tests

5. **Running from WSL/Linux**
   ```bash
   # Use Windows PowerShell
   powershell.exe -File ./run-tests.ps1
   
   # Or if you have PowerShell Core installed
   pwsh ./run-tests.ps1
   ```

## Requirements

- PowerShell 5.1 or higher
- Pester 5.0 or higher
- Administrator privileges for System tests
- BurntToast module for live progress notifications (auto-installed if needed)