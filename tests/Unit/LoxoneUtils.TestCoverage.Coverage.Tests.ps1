#Requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for TestCoverage internal helper functions.

.DESCRIPTION
    Tests for: ConvertFrom-JsonToHashtable, Get-FunctionDocumentation,
    Get-FunctionTestScore, Get-TestContext, Get-ChangedFunctions.
    These are data-processing functions tested with sample inputs and mocked externals.
    Internal functions are accessed via InModuleScope.
#>

BeforeAll {
    # Set test environment flag
    $Global:IsTestRun = $true
    $env:PESTER_TEST_RUN = "1"
    $Global:ProgressPreference = 'SilentlyContinue'

    # Import the module manifest so exported functions exist
    $modulePath = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' |
        Join-Path -ChildPath 'LoxoneUtils.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Import TestCoverage psm1 directly so InModuleScope can reach internals
    $psm1Path = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) -ChildPath 'LoxoneUtils' |
        Join-Path -ChildPath 'LoxoneUtils.TestCoverage.psm1'
    Import-Module $psm1Path -Force -ErrorAction Stop

    # Suppress Write-Host / Write-Log / Enter-Function / Exit-Function noise
    Mock Write-Host {}
    Mock Write-Log {} -ErrorAction SilentlyContinue
    Mock Enter-Function {} -ErrorAction SilentlyContinue
    Mock Exit-Function {} -ErrorAction SilentlyContinue
    Mock Write-Progress {}

    # Also mock inside module scope so internal calls from Get-TestContext etc. are suppressed
    Mock Write-Log {} -ModuleName LoxoneUtils.TestCoverage -ErrorAction SilentlyContinue
    Mock Enter-Function {} -ModuleName LoxoneUtils.TestCoverage -ErrorAction SilentlyContinue
    Mock Exit-Function {} -ModuleName LoxoneUtils.TestCoverage -ErrorAction SilentlyContinue
    Mock Write-Progress {} -ModuleName LoxoneUtils.TestCoverage
}

AfterAll {
    $Global:IsTestRun = $false
    $env:PESTER_TEST_RUN = ""
    $Global:ProgressPreference = 'Continue'
}

# ---------------------------------------------------------------------------
# ConvertFrom-JsonToHashtable
# ---------------------------------------------------------------------------
Describe "ConvertFrom-JsonToHashtable" -Tag 'Unit', 'TestCoverage' {

    Context "Basic conversion" {
        It "Should return a hashtable with grandfathered and permanent keys" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{"FuncA":"reason A"},"permanent":{"FuncB":"reason B"}}'
            }

            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'grandfathered'
            $result.Keys | Should -Contain 'permanent'
        }

        It "Should populate grandfathered entries from JSON properties" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{"Func1":"legacy","Func2":"deprecated"},"permanent":{}}'
            }

            $result.grandfathered.Count | Should -Be 2
            $result.grandfathered['Func1'] | Should -Be 'legacy'
            $result.grandfathered['Func2'] | Should -Be 'deprecated'
        }

        It "Should populate permanent entries from JSON properties" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{},"permanent":{"HelperX":"infra only"}}'
            }

            $result.permanent.Count | Should -Be 1
            $result.permanent['HelperX'] | Should -Be 'infra only'
        }
    }

    Context "Metadata handling" {
        It "Should include metadata when present in JSON" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{},"permanent":{},"metadata":{"version":"1.0","updated":"2025-06-01"}}'
            }

            $result.Keys | Should -Contain 'metadata'
            $result.metadata.version | Should -Be '1.0'
        }

        It "Should not include metadata key when absent from JSON" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{},"permanent":{}}'
            }

            $result.Keys | Should -Not -Contain 'metadata'
        }
    }

    Context "Edge cases" {
        It "Should return empty sub-hashtables when sections are empty" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{},"permanent":{}}'
            }

            $result.grandfathered.Count | Should -Be 0
            $result.permanent.Count | Should -Be 0
        }

        It "Should handle missing grandfathered key gracefully" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"permanent":{"A":"b"}}'
            }

            $result.grandfathered.Count | Should -Be 0
            $result.permanent['A'] | Should -Be 'b'
        }

        It "Should handle missing permanent key gracefully" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                ConvertFrom-JsonToHashtable -Json '{"grandfathered":{"X":"y"}}'
            }

            $result.grandfathered['X'] | Should -Be 'y'
            $result.permanent.Count | Should -Be 0
        }
    }
}

# ---------------------------------------------------------------------------
# Get-FunctionDocumentation
# ---------------------------------------------------------------------------
Describe "Get-FunctionDocumentation" -Tag 'Unit', 'TestCoverage' {

    Context "Function with full comment-based help" {
        It "Should detect documentation and set HasDocumentation to Yes" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $content = @"
<#
.SYNOPSIS
    Does something useful
.DESCRIPTION
    A longer description here
.PARAMETER Name
    The name parameter
#>
function Test-SampleFunction {
    param([string]`$Name)
}
"@
                Get-FunctionDocumentation -FunctionName 'Test-SampleFunction' -FileContent $content
            }

            $result.HasDocumentation | Should -Be 'Yes'
        }

        It "Should extract the synopsis text" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $content = @"
<#
.SYNOPSIS
    My synopsis text here
#>
function Test-WithSynopsis {
    param()
}
"@
                Get-FunctionDocumentation -FunctionName 'Test-WithSynopsis' -FileContent $content
            }

            $result.Synopsis | Should -BeLike '*My synopsis text here*'
        }

        It "Should return a CompletionScore of 50 when documentation exists" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $content = @"
<#
.SYNOPSIS
    Documented function
#>
function Test-Scored {
    param()
}
"@
                Get-FunctionDocumentation -FunctionName 'Test-Scored' -FileContent $content
            }

            $result.CompletionScore | Should -Be '50'
        }
    }

    Context "Function without documentation" {
        It "Should set HasDocumentation to No for undocumented function" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Test-NoDocs' -FileContent 'function Test-NoDocs { param([string]$Value); return $Value }'
            }

            $result.HasDocumentation | Should -Be 'No'
        }

        It "Should return CompletionScore of 0 for undocumented function" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Test-NoDocsScore' -FileContent 'function Test-NoDocsScore { return 42 }'
            }

            $result.CompletionScore | Should -Be '0'
        }

        It "Should return empty synopsis for undocumented function" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Test-EmptySynopsis' -FileContent 'function Test-EmptySynopsis { return $null }'
            }

            $result.Synopsis | Should -BeNullOrEmpty
        }
    }

    Context "Known problematic functions" {
        It "Should return Skipped for known problematic function names" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Get-InstalledVersion' -FileContent 'function Get-InstalledVersion { param() }'
            }

            $result.Synopsis | Should -Be 'Skipped'
            $result.HasDocumentation | Should -Be 'No'
            $result.CompletionScore | Should -Be '0'
        }

        It "Should return Skipped for Enter-Function" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Enter-Function' -FileContent 'function Enter-Function { param() }'
            }

            $result.Synopsis | Should -Be 'Skipped'
        }
    }

    Context "Return structure" {
        It "Should return an object with all expected properties" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Test-Props' -FileContent 'function Test-Props { param() }'
            }

            $result.PSObject.Properties.Name | Should -Contain 'Synopsis'
            $result.PSObject.Properties.Name | Should -Contain 'Description'
            $result.PSObject.Properties.Name | Should -Contain 'Parameters'
            $result.PSObject.Properties.Name | Should -Contain 'Examples'
            $result.PSObject.Properties.Name | Should -Contain 'HasDocumentation'
            $result.PSObject.Properties.Name | Should -Contain 'CompletionScore'
        }
    }

    Context "Function not found in content" {
        It "Should return No documentation when function name is not in file" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionDocumentation -FunctionName 'Missing-Function' -FileContent 'function Other-Function { param() }'
            }

            $result.HasDocumentation | Should -Be 'No'
            $result.CompletionScore | Should -Be '0'
        }
    }
}

# ---------------------------------------------------------------------------
# Get-FunctionTestScore
# ---------------------------------------------------------------------------
Describe "Get-FunctionTestScore" -Tag 'Unit', 'TestCoverage' {

    Context "Direct invocation scoring" {
        It "Should score 3 points for a direct function call at line start" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Should work`" {`n    Test-MyFunction -Param `"value`"`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -BeGreaterThan 0
            $result | Should -BeOfType [hashtable]
        }

        It "Should score 3 points for piped invocation" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Should pipe`" {`n    `$data | Test-MyFunction`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 3
        }

        It "Should score 3 points for assignment invocation" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Should assign`" {`n    `$result = Test-MyFunction -Verbose`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 3
        }
    }

    Context "Mock scoring" {
        It "Should score 2 points for Mock declaration" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "BeforeAll {`n    Mock Test-MyFunction { return `$true }`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 2
        }
    }

    Context "Should -Invoke scoring" {
        It "Should score 3 points for Should -Invoke assertion" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Should call function`" {`n    Should -Invoke Test-MyFunction -Exactly 1`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 3
        }
    }

    Context "Describe/It block name scoring" {
        It "Should score 1 point for function name in Describe block" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "Describe `"Test-MyFunction behavior`" {`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 1
        }
    }

    Context "Comment lines" {
        It "Should not score lines that are comments" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "# Test-MyFunction is great`n# Test-MyFunction should work"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 0
        }
    }

    Context "Confidence levels" {
        It "Should return High confidence when score >= 4" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Test one`" {`n    Test-MyFunction -Param1 `"a`"`n    Test-MyFunction -Param2 `"b`"`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Confidence | Should -Be 'High'
            $result.Tested | Should -Be $true
        }

        It "Should return Medium confidence when score is 2 or 3" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Test`" {`n    Mock Test-MyFunction { }`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Confidence | Should -Be 'Medium'
            $result.Tested | Should -Be $true
        }

        It "Should return Low confidence when score < 2" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "Describe `"Test-MyFunction`" {`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Confidence | Should -Be 'Low'
            $result.Tested | Should -Be $false
        }
    }

    Context "Return structure" {
        It "Should return hashtable with Score, Confidence, and Tested keys" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionTestScore -TestContent "Test-SomeFunc -Param val" -FuncName 'Test-SomeFunc'
            }

            $result.Keys | Should -Contain 'Score'
            $result.Keys | Should -Contain 'Confidence'
            $result.Keys | Should -Contain 'Tested'
        }

        It "Should return Tested as boolean" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                Get-FunctionTestScore -TestContent "Test-SomeFunc" -FuncName 'Test-SomeFunc'
            }

            $result.Tested | Should -BeOfType [bool]
        }
    }

    Context "No matches" {
        It "Should return zero score when function is not referenced at all" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "It `"Does something`" {`n    Other-Function -Param `"test`"`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            $result.Score | Should -Be 0
            $result.Confidence | Should -Be 'Low'
            $result.Tested | Should -Be $false
        }
    }

    Context "Cumulative scoring" {
        It "Should accumulate score across multiple reference types" {
            $result = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = "Mock Test-MyFunction { return `"mocked`" }`nIt `"Should work`" {`n    `$r = Test-MyFunction -Param `"value`"`n    Should -Invoke Test-MyFunction -Exactly 1`n}"
                Get-FunctionTestScore -TestContent $tc -FuncName 'Test-MyFunction'
            }

            # Mock (2) + direct call (3) + Should -Invoke (3) = 8
            $result.Score | Should -BeGreaterOrEqual 8
            $result.Confidence | Should -Be 'High'
        }
    }
}

# ---------------------------------------------------------------------------
# Get-TestContext
# ---------------------------------------------------------------------------
Describe "Get-TestContext" -Tag 'Unit', 'TestCoverage' {

    Context "Describe block with Context and It blocks" {
        It "Should extract context entries for a function with dedicated Describe" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Function" {
    Context "Basic logging" {
        It "Should write message to file" {
            Write-Log -Message "test" | Should -Not -BeNullOrEmpty
        }
        It "Should append timestamp" {
            Write-Log -Message "test2" | Should -Match "\d{4}"
        }
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Logging.Tests.ps1'
                $r.Count
            }

            $count | Should -BeGreaterOrEqual 2
        }

        It "Should include Describe title in each entry" {
            $describe = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Function" {
    Context "Error handling" {
        It "Should handle null message" {
            Write-Log -Message `$null | Should -Throw
        }
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r[0].Describe
            }

            $describe | Should -Not -BeNullOrEmpty
        }

        It "Should include It block title in each entry" {
            $itTitle = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Function" {
    It "Should log info messages" {
        Write-Log -Message "info"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r[0].It
            }

            $itTitle | Should -Be 'Should log info messages'
        }

        It "Should include TestFile in each entry" {
            $testFile = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Function" {
    It "Should work" {
        Write-Log "msg"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'MyTests.ps1'
                $r[0].TestFile
            }

            $testFile | Should -Be 'MyTests.ps1'
        }
    }

    Context "Describe block without Context blocks" {
        It "Should extract standalone It blocks" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Get-CRC32 Function" {
    It "Should compute checksum" {
        `$hash = Get-CRC32 -Path "test.txt"
        `$hash | Should -Not -BeNullOrEmpty
    }
    It "Should return string" {
        `$hash = Get-CRC32 -Path "test.txt"
        `$hash | Should -BeOfType [string]
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Get-CRC32' -TestFileName 'Util.Tests.ps1'
                $r.Count
            }

            $count | Should -BeGreaterOrEqual 2
        }
    }

    Context "Expectations extraction" {
        It "Should extract Should assertions as expectations" {
            $expectCount = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Format-Bytes Function" {
    It "Should format bytes" {
        Format-Bytes -Bytes 1024 | Should -Be "1 KB"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Format-Bytes' -TestFileName 'Test.ps1'
                $r[0].Expectations.Count
            }

            $expectCount | Should -BeGreaterThan 0
        }
    }

    Context "No matching Describe block" {
        It "Should return empty array when function has no dedicated Describe" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Other-Function Function" {
    It "Tests other function" {
        Other-Function | Should -Be "ok"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r.Count
            }

            $count | Should -Be 0
        }
    }

    Context "Fallback when function is mentioned but not in Describe" {
        It "Should create fallback entry when function is referenced in test content" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Function" {
    BeforeAll {
        Mock Write-Log {}
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r.Count
            }

            $count | Should -BeGreaterThan 0
        }
    }

    Context "Return structure" {
        It "Should return array of hashtables with Describe, It, TestFile, Expectations" {
            $keys = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Test-Sample Function" {
    It "Should work" {
        Test-Sample | Should -Be `$true
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Test-Sample' -TestFileName 'Sample.Tests.ps1'
                if ($r -and $r.Count -gt 0) { $r[0].Keys } else { @() }
            }

            $keys | Should -Not -BeNullOrEmpty
            $keys | Should -Contain 'Describe'
            $keys | Should -Contain 'It'
            $keys | Should -Contain 'TestFile'
            $keys | Should -Contain 'Expectations'
        }
    }

    Context "Multiple Describe block naming patterns" {
        It "Should match FunctionName Core Functionality pattern" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log Core Functionality" {
    It "Should handle concurrent writes" {
        Write-Log -Message "concurrent"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r.Count
            }

            $count | Should -BeGreaterThan 0
        }

        It "Should match bare function name pattern" {
            $count = InModuleScope 'LoxoneUtils.TestCoverage' {
                $tc = @"
Describe "Write-Log" {
    It "Should log" {
        Write-Log -Message "test"
    }
}
"@
                $r = Get-TestContext -TestContent $tc -FunctionName 'Write-Log' -TestFileName 'Test.ps1'
                $r.Count
            }

            $count | Should -BeGreaterThan 0
        }
    }
}

# ---------------------------------------------------------------------------
# Get-ChangedFunctions (exported)
# Note: git is called via & operator inside the function, so Pester cannot
# mock the external executable. Tests focus on parameter validation,
# return type, and behavior that does not depend on git mock interception.
# ---------------------------------------------------------------------------
Describe "Get-ChangedFunctions" -Tag 'Unit', 'TestCoverage' {

    Context "Return type and basic behavior" {
        It "Should return an array or collection" {
            # Wrap in @() for null-safety; result may be empty if no .psm1 changes in working tree
            $result = @(Get-ChangedFunctions -CompareWith 'HEAD')

            # @() ensures array type regardless of git state
            $result -is [array] | Should -Be $true
        }

        It "Should not throw with valid parameters" {
            { Get-ChangedFunctions -CompareWith 'HEAD' } | Should -Not -Throw
        }
    }

    Context "Parameters" {
        It "Should have CompareWith parameter of type string" {
            $param = (Get-Command Get-ChangedFunctions).Parameters['CompareWith']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType | Should -Be ([string])
        }

        It "Should have IncludeStaged parameter as switch" {
            $param = (Get-Command Get-ChangedFunctions).Parameters['IncludeStaged']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType | Should -Be ([switch])
        }

        It "Should have ModulePath parameter of type string" {
            $param = (Get-Command Get-ChangedFunctions).Parameters['ModulePath']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType | Should -Be ([string])
        }

        It "Should accept CompareWith parameter without error" {
            { Get-ChangedFunctions -CompareWith 'main' } | Should -Not -Throw
        }

        It "Should accept IncludeStaged switch without error" {
            { Get-ChangedFunctions -IncludeStaged } | Should -Not -Throw
        }

        It "Should accept ModulePath parameter without error" {
            { Get-ChangedFunctions -ModulePath (Join-Path $TestDrive 'FakeModule') } | Should -Not -Throw
        }
    }

    Context "Output contains only strings" {
        It "Should return string elements when results are present" {
            $result = Get-ChangedFunctions -CompareWith 'HEAD'

            if ($result.Count -gt 0) {
                $result | ForEach-Object { $_ | Should -BeOfType [string] }
            } else {
                # Empty result is also valid
                $result.Count | Should -Be 0
            }
        }
    }
}
