# Tests for LoxoneUtils.ConsoleProgress - Get-ProgressBar function

BeforeAll {
    if (-not $Global:LoxoneUtilsPreloaded) {
        $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' | Join-Path -ChildPath 'LoxoneUtils.psd1'
        Import-Module $modulePath -Force -ErrorAction Stop
    } else {
        $modulePath = $Global:LoxoneUtilsModulePath
        if (-not (Get-Module LoxoneUtils)) {
            Import-Module $modulePath -ErrorAction Stop
        }
    }
    $Global:SuppressLoxoneToastInit = $true

    $script:TestTempPath = Join-Path $TestDrive "Tests"
    New-Item -ItemType Directory -Path $script:TestTempPath -Force | Out-Null
    $Global:LogFile = Join-Path $script:TestTempPath 'test.log'
    New-Item -ItemType File -Path $Global:LogFile -Force | Out-Null

    # Detect per-character multiplier for block chars in current PowerShell version.
    # Windows PowerShell 5.1 reads UTF-8 block chars as 3-char sequences; PS 7+ as 1 char.
    $singleBlock = Get-ProgressBar -Progress 100 -Width 1
    $barPart = ($singleBlock -replace '^\[', '' -replace '\].*$', '')
    $script:CharMultiplier = $barPart.Length  # 1 on PS7, 3 on WinPS 5.1
}

AfterAll {
    Remove-Variable -Name LogFile -Scope Global -ErrorAction SilentlyContinue
}

Describe "Get-ProgressBar" -Tag 'Unit' {

    Context "Returns correct format" {

        It "Returns a string that starts with '[' and ends with a percentage" {
            $result = Get-ProgressBar -Progress 50
            $result | Should -Match '^\[.*\]\s+\d+%$'
        }

        It "Contains the progress percentage value in the output" {
            $result = Get-ProgressBar -Progress 73
            $result | Should -BeLike '*73%'
        }

        It "Returns a non-empty string" {
            $result = Get-ProgressBar -Progress 0
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context "Progress at boundary values" {

        It "Displays 0% progress" {
            $result = Get-ProgressBar -Progress 0
            $result | Should -BeLike '*0%'
            $result | Should -Match '^\['
        }

        It "Displays 50% progress" {
            $result = Get-ProgressBar -Progress 50
            $result | Should -BeLike '*50%'
            $result.Length | Should -BeGreaterThan 0
        }

        It "Displays 100% progress" {
            $result = Get-ProgressBar -Progress 100
            $result | Should -BeLike '*100%'
        }
    }

    Context "Progress bar width calculation" {

        It "Uses default width of 30 when no width specified" {
            $result = Get-ProgressBar -Progress 50
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $barContent.Length | Should -Be (30 * $script:CharMultiplier)
        }

        It "Respects custom width parameter of 20" {
            $result = Get-ProgressBar -Progress 50 -Width 20
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $barContent.Length | Should -Be (20 * $script:CharMultiplier)
        }

        It "Respects a larger custom width of 50" {
            $result = Get-ProgressBar -Progress 50 -Width 50
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $barContent.Length | Should -Be (50 * $script:CharMultiplier)
        }

        It "Handles width of 1" {
            $result = Get-ProgressBar -Progress 100 -Width 1
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $barContent.Length | Should -Be (1 * $script:CharMultiplier)
        }

        It "Bar length scales linearly with width" {
            $bar10 = Get-ProgressBar -Progress 50 -Width 10
            $bar20 = Get-ProgressBar -Progress 50 -Width 20
            $len10 = ($bar10 -replace '^\[', '' -replace '\].*$', '').Length
            $len20 = ($bar20 -replace '^\[', '' -replace '\].*$', '').Length
            $len20 | Should -Be ($len10 * 2)
        }
    }

    Context "Filled and remaining block proportions" {

        It "At 0% the bar content differs from 100% bar content" {
            $bar0 = Get-ProgressBar -Progress 0 -Width 10
            $bar100 = Get-ProgressBar -Progress 100 -Width 10
            $content0 = ($bar0 -replace '^\[', '' -replace '\].*$', '')
            $content100 = ($bar100 -replace '^\[', '' -replace '\].*$', '')
            # Both have same length but different characters
            $content0.Length | Should -Be $content100.Length
            $content0 | Should -Not -Be $content100
        }

        It "At 0% bar is identical to a pure-unfilled bar" {
            $bar0 = Get-ProgressBar -Progress 0 -Width 10
            $content0 = ($bar0 -replace '^\[', '' -replace '\].*$', '')
            # All chars should be the same (all unfilled)
            $uniqueSegments = $content0 -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' } | Sort-Object -Unique
            $uniqueSegments.Count | Should -Be 1
        }

        It "At 100% bar is identical to a pure-filled bar" {
            $bar100 = Get-ProgressBar -Progress 100 -Width 10
            $content100 = ($bar100 -replace '^\[', '' -replace '\].*$', '')
            # All chars should be the same (all filled)
            $uniqueSegments = $content100 -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' } | Sort-Object -Unique
            $uniqueSegments.Count | Should -Be 1
        }

        It "At 50% with width 10, bar has two distinct character types" {
            $result = Get-ProgressBar -Progress 50 -Width 10
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            # Split into character-sized segments and count unique types
            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $uniqueTypes = $segments | Sort-Object -Unique
            $uniqueTypes.Count | Should -Be 2
        }

        It "At 50% with width 10, filled portion is half the bar" {
            $result50 = Get-ProgressBar -Progress 50 -Width 10
            $barContent = ($result50 -replace '^\[', '' -replace '\].*$', '')

            # Get the filled character type from a 100% bar
            $bar100 = Get-ProgressBar -Progress 100 -Width 1
            $filledChar = ($bar100 -replace '^\[', '' -replace '\].*$', '')

            # Count how many segments match the filled type
            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $filledCount = ($segments | Where-Object { $_ -eq $filledChar }).Count
            $filledCount | Should -Be 5
        }

        It "At 30% with width 10, 3 blocks are filled and 7 unfilled" {
            $result = Get-ProgressBar -Progress 30 -Width 10
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')

            # Get filled/unfilled reference chars
            $filledRef = (Get-ProgressBar -Progress 100 -Width 1) -replace '^\[', '' -replace '\].*$', ''
            $unfilledRef = (Get-ProgressBar -Progress 0 -Width 1) -replace '^\[', '' -replace '\].*$', ''

            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $filledCount = ($segments | Where-Object { $_ -eq $filledRef }).Count
            $unfilledCount = ($segments | Where-Object { $_ -eq $unfilledRef }).Count
            $filledCount | Should -Be 3
            $unfilledCount | Should -Be 7
        }
    }

    Context "Edge cases" {

        It "Handles progress values that produce fractional block counts (33% of 10 = floor to 3)" {
            $result = Get-ProgressBar -Progress 33 -Width 10
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $filledRef = (Get-ProgressBar -Progress 100 -Width 1) -replace '^\[', '' -replace '\].*$', ''
            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $filledCount = ($segments | Where-Object { $_ -eq $filledRef }).Count
            $filledCount | Should -Be 3
        }

        It "Handles progress of 1% with width 10 (floors to 0 filled)" {
            $result = Get-ProgressBar -Progress 1 -Width 10
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $filledRef = (Get-ProgressBar -Progress 100 -Width 1) -replace '^\[', '' -replace '\].*$', ''
            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $filledCount = ($segments | Where-Object { $_ -eq $filledRef }).Count
            $filledCount | Should -Be 0
        }

        It "Handles progress of 99% with width 10 (floors to 9 filled)" {
            $result = Get-ProgressBar -Progress 99 -Width 10
            $barContent = ($result -replace '^\[', '' -replace '\].*$', '')
            $filledRef = (Get-ProgressBar -Progress 100 -Width 1) -replace '^\[', '' -replace '\].*$', ''
            $segments = $barContent -split '(.{' + $script:CharMultiplier + '})' | Where-Object { $_ -ne '' }
            $filledCount = ($segments | Where-Object { $_ -eq $filledRef }).Count
            $filledCount | Should -Be 9
        }
    }
}
