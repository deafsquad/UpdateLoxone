# LoxoneUtils.TestTracking.psm1
# Module for tracking individual test assertions and their results

# Global storage for assertion results
$Global:LoxoneTestAssertions = @{}
$Global:CurrentTestContext = $null
$Global:AssertionTrackingEnabled = $false
$Global:AssertionResultCache = @{}
$Global:AssertionCacheTimeout = [TimeSpan]::FromMinutes(30)
$Global:LastAssertionCacheTime = [DateTime]::MinValue

function Enable-AssertionTracking {
    <#
    .SYNOPSIS
    Enables detailed assertion tracking for tests
    #>
    [CmdletBinding()]
    param()
    
    $Global:AssertionTrackingEnabled = $true
    $Global:LoxoneTestAssertions = @{}
    Write-Verbose "Assertion tracking enabled"
}

function Disable-AssertionTracking {
    <#
    .SYNOPSIS
    Disables assertion tracking and clears collected data
    #>
    [CmdletBinding()]
    param()
    
    $Global:AssertionTrackingEnabled = $false
    $Global:LoxoneTestAssertions = @{}
    $Global:CurrentTestContext = $null
    Write-Verbose "Assertion tracking disabled"
}

function Set-TestContext {
    <#
    .SYNOPSIS
    Sets the current test context for assertion tracking
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [string]$FunctionName,
        
        [string]$FileName = ""
    )
    
    if (-not $Global:AssertionTrackingEnabled) { return }
    
    $Global:CurrentTestContext = @{
        TestName = $TestName
        FunctionName = $FunctionName
        FileName = $FileName
        Assertions = @()
    }
    
    # Initialize storage for this test if needed
    $testKey = "$FunctionName.$TestName"
    if (-not $Global:LoxoneTestAssertions.ContainsKey($testKey)) {
        $Global:LoxoneTestAssertions[$testKey] = @{
            TestName = $TestName
            FunctionName = $FunctionName
            FileName = $FileName
            Assertions = @()
            StartTime = Get-Date
        }
    }
}

function Get-TestAssertionResults {
    <#
    .SYNOPSIS
    Gets assertion results for a specific test or all tests
    #>
    [CmdletBinding()]
    param(
        [string]$TestName = "",
        [string]$FunctionName = ""
    )
    
    if ($TestName -and $FunctionName) {
        $testKey = "$FunctionName.$TestName"
        return $Global:LoxoneTestAssertions[$testKey]
    } elseif ($FunctionName) {
        # Return all tests for a function
        return $Global:LoxoneTestAssertions.GetEnumerator() | 
            Where-Object { $_.Value.FunctionName -eq $FunctionName } |
            ForEach-Object { $_.Value }
    } else {
        # Return all assertion results
        return $Global:LoxoneTestAssertions
    }
}

function Export-TestAssertionResults {
    <#
    .SYNOPSIS
    Exports assertion tracking results to a file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [ValidateSet('JSON', 'XML', 'CSV')]
        [string]$Format = 'JSON'
    )
    
    $results = $Global:LoxoneTestAssertions
    
    switch ($Format) {
        'JSON' {
            $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }
        'XML' {
            $xml = [System.Xml.XmlDocument]::new()
            $root = $xml.CreateElement("TestAssertions")
            $xml.AppendChild($root) | Out-Null
            
            foreach ($test in $results.GetEnumerator()) {
                $testNode = $xml.CreateElement("Test")
                $testNode.SetAttribute("name", $test.Key)
                $testNode.SetAttribute("function", $test.Value.FunctionName)
                
                foreach ($assertion in $test.Value.Assertions) {
                    $assertNode = $xml.CreateElement("Assertion")
                    $assertNode.SetAttribute("operator", $assertion.Operator)
                    $assertNode.SetAttribute("passed", $assertion.Passed)
                    $assertNode.SetAttribute("description", $assertion.Description)
                    
                    if ($assertion.ErrorMessage) {
                        $errorNode = $xml.CreateElement("Error")
                        $errorNode.InnerText = $assertion.ErrorMessage
                        $assertNode.AppendChild($errorNode) | Out-Null
                    }
                    
                    $testNode.AppendChild($assertNode) | Out-Null
                }
                
                $root.AppendChild($testNode) | Out-Null
            }
            
            $xml.Save($Path)
        }
        'CSV' {
            $csvData = @()
            foreach ($test in $results.GetEnumerator()) {
                foreach ($assertion in $test.Value.Assertions) {
                    $csvData += [PSCustomObject]@{
                        TestName = $test.Key
                        FunctionName = $test.Value.FunctionName
                        FileName = $test.Value.FileName
                        Operator = $assertion.Operator
                        Description = $assertion.Description
                        Passed = $assertion.Passed
                        ErrorMessage = $assertion.ErrorMessage
                        Timestamp = $assertion.Timestamp
                    }
                }
            }
            $csvData | Export-Csv -Path $Path -NoTypeInformation
        }
    }
}

# Helper function to create a Should alias that uses our wrapper

function Get-CachedAssertionResults {
    <#
    .SYNOPSIS
    Retrieves cached assertion results if available and not expired
    #>
    [CmdletBinding()]
    param(
        [string]$CacheKey = "default"
    )
    
    if ($Global:AssertionResultCache.ContainsKey($CacheKey)) {
        $cacheEntry = $Global:AssertionResultCache[$CacheKey]
        $timeSinceCached = [DateTime]::Now - $cacheEntry.Timestamp
        
        if ($timeSinceCached -lt $Global:AssertionCacheTimeout) {
            Write-Verbose "Returning cached assertion results for key: $CacheKey"
            return $cacheEntry.Data
        } else {
            Write-Verbose "Cache expired for key: $CacheKey"
            $Global:AssertionResultCache.Remove($CacheKey)
        }
    }
    
    return $null
}

function Set-CachedAssertionResults {
    <#
    .SYNOPSIS
    Caches assertion results with a timestamp
    #>
    [CmdletBinding()]
    param(
        [string]$CacheKey = "default",
        [hashtable]$Data
    )
    
    $Global:AssertionResultCache[$CacheKey] = @{
        Timestamp = [DateTime]::Now
        Data = $Data
    }
    
    Write-Verbose "Cached assertion results for key: $CacheKey"
}

function Import-AssertionResults {
    <#
    .SYNOPSIS
    Imports assertion results from a file with caching support
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [ValidateSet('JSON', 'XML', 'CSV')]
        [string]$Format = 'JSON'
    )
    
    if (-not (Test-Path $Path)) {
        Write-Warning "Assertion results file not found: $Path"
        return @{}
    }
    
    # Check cache first
    $cacheKey = "file:$Path"
    $fileInfo = Get-Item $Path
    $cachedData = Get-CachedAssertionResults -CacheKey $cacheKey
    
    if ($cachedData -and $Global:LastAssertionCacheTime -gt $fileInfo.LastWriteTime) {
        return $cachedData
    }
    
    try {
        $content = switch ($Format) {
            'JSON' {
                # Note: -AsHashtable is only available in PowerShell 6+
                $jsonContent = Get-Content $Path -Raw | ConvertFrom-Json
                # Convert to hashtable manually
                $ht = @{}
                foreach ($prop in $jsonContent.PSObject.Properties) {
                    $ht[$prop.Name] = $prop.Value
                }
                $ht
            }
            'XML' {
                $xml = [xml](Get-Content $Path -Raw)
                $results = @{}
                foreach ($test in $xml.TestAssertions.Test) {
                    $testData = @{
                        TestName = $test.name
                        FunctionName = $test.function
                        FileName = $test.filename
                        Assertions = @()
                    }
                    
                    foreach ($assertion in $test.Assertion) {
                        $testData.Assertions += @{
                            Operator = $assertion.operator
                            Passed = [bool]::Parse($assertion.passed)
                            Description = $assertion.description
                            ErrorMessage = $assertion.Error.InnerText
                            Timestamp = if ($assertion.timestamp) { [DateTime]::Parse($assertion.timestamp) } else { [DateTime]::MinValue }
                        }
                    }
                    
                    $results[$test.name] = $testData
                }
                $results
            }
            'CSV' {
                $csv = Import-Csv $Path
                $results = @{}
                foreach ($row in $csv) {
                    $key = $row.TestName
                    if (-not $results.ContainsKey($key)) {
                        $results[$key] = @{
                            TestName = $row.TestName
                            FunctionName = $row.FunctionName
                            FileName = $row.FileName
                            Assertions = @()
                        }
                    }
                    
                    $results[$key].Assertions += @{
                        Operator = $row.Operator
                        Description = $row.Description
                        Passed = [bool]::Parse($row.Passed)
                        ErrorMessage = $row.ErrorMessage
                        Timestamp = if ($row.Timestamp) { [DateTime]::Parse($row.Timestamp) } else { [DateTime]::MinValue }
                    }
                }
                $results
            }
        }
        
        # Cache the results
        Set-CachedAssertionResults -CacheKey $cacheKey -Data $content
        $Global:LastAssertionCacheTime = [DateTime]::Now
        
        return $content
    }
    catch {
        Write-Warning "Failed to import assertion results: $_"
        return @{}
    }
}

function Merge-AssertionResults {
    <#
    .SYNOPSIS
    Merges multiple assertion result sets, keeping the most recent data
    #>
    [CmdletBinding()]
    param(
        [hashtable[]]$ResultSets
    )
    
    $merged = @{}
    
    foreach ($resultSet in $ResultSets) {
        foreach ($testKey in $resultSet.Keys) {
            if (-not $merged.ContainsKey($testKey)) {
                $merged[$testKey] = $resultSet[$testKey]
            } else {
                # Merge assertions, keeping the most recent based on timestamp
                $existingAssertions = $merged[$testKey].Assertions
                $newAssertions = $resultSet[$testKey].Assertions
                
                # Create a lookup by description
                $assertionMap = @{}
                foreach ($assertion in $existingAssertions) {
                    $assertionMap[$assertion.Description] = $assertion
                }
                
                foreach ($assertion in $newAssertions) {
                    $existing = $assertionMap[$assertion.Description]
                    if (-not $existing -or $assertion.Timestamp -gt $existing.Timestamp) {
                        $assertionMap[$assertion.Description] = $assertion
                    }
                }
                
                $merged[$testKey].Assertions = @($assertionMap.Values)
            }
        }
    }
    
    return $merged
}

function Find-AssertionMatch {
    <#
    .SYNOPSIS
    Advanced pattern matching to link test goals/expectations with assertion results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Goal,
        
        [Parameter(Mandatory)]
        [hashtable]$AssertionResults,
        
        [switch]$ReturnBestMatch
    )
    
    $matches = @()
    
    foreach ($assertionDesc in $AssertionResults.Keys) {
        $score = 0
        $matchDetails = @{
            AssertionDescription = $assertionDesc
            Goal = $Goal
            Score = 0
            MatchType = 'None'
        }
        
        # Exact match (case insensitive)
        if ($assertionDesc -eq $Goal) {
            $matchDetails.Score = 100
            $matchDetails.MatchType = 'Exact'
            $matches += $matchDetails
            continue
        }
        
        # Normalize strings for comparison
        $normalizedGoal = $Goal.ToLower().Trim()
        $normalizedAssertion = $assertionDesc.ToLower().Trim()
        
        # Contains match (both directions)
        if ($normalizedAssertion -like "*$normalizedGoal*") {
            $matchDetails.Score = 80
            $matchDetails.MatchType = 'AssertionContainsGoal'
        }
        elseif ($normalizedGoal -like "*$normalizedAssertion*") {
            $matchDetails.Score = 75
            $matchDetails.MatchType = 'GoalContainsAssertion'
        }
        
        # Extract key terms and match
        $goalKeywords = ExtractKeywords -Text $normalizedGoal
        $assertionKeywords = ExtractKeywords -Text $normalizedAssertion
        
        if ($goalKeywords.Count -gt 0 -and $assertionKeywords.Count -gt 0) {
            $commonKeywords = $goalKeywords | Where-Object { $assertionKeywords -contains $_ }
            $keywordScore = ($commonKeywords.Count / [Math]::Max($goalKeywords.Count, $assertionKeywords.Count)) * 70
            
            if ($keywordScore -gt $matchDetails.Score) {
                $matchDetails.Score = [Math]::Round($keywordScore)
                $matchDetails.MatchType = 'KeywordMatch'
                $matchDetails.CommonKeywords = $commonKeywords
            }
        }
        
        # Operator-based matching
        $operators = @{
            'Be' = @('equals', 'is', 'should be', 'must be')
            'BeGreaterThan' = @('greater than', 'more than', 'exceeds', 'above')
            'BeLessThan' = @('less than', 'below', 'under')
            'Contain' = @('contains', 'includes', 'has')
            'Match' = @('matches', 'matches pattern', 'regex')
            'BeOfType' = @('type', 'is type', 'should be type')
            'Exist' = @('exists', 'present', 'available')
            'HaveCount' = @('count', 'number', 'length', 'size')
        }
        
        foreach ($op in $operators.Keys) {
            if ($assertionDesc -match "expects.*$op" -or $assertionDesc -match "should.*$op") {
                foreach ($synonym in $operators[$op]) {
                    if ($normalizedGoal -like "*$synonym*") {
                        if (50 -gt $matchDetails.Score) {
                            $matchDetails.Score = 50
                            $matchDetails.MatchType = 'OperatorMatch'
                            $matchDetails.Operator = $op
                        }
                        break
                    }
                }
            }
        }
        
        # Value matching (numbers, strings in quotes)
        $goalValues = ExtractValues -Text $Goal
        $assertionValues = ExtractValues -Text $assertionDesc
        
        if ($goalValues.Count -gt 0 -and $assertionValues.Count -gt 0) {
            $commonValues = $goalValues | Where-Object { $assertionValues -contains $_ }
            if ($commonValues.Count -gt 0 -and 40 -gt $matchDetails.Score) {
                $matchDetails.Score = 40
                $matchDetails.MatchType = 'ValueMatch'
                $matchDetails.CommonValues = $commonValues
            }
        }
        
        if ($matchDetails.Score -gt 0) {
            $matches += $matchDetails
        }
    }
    
    if ($ReturnBestMatch -and $matches.Count -gt 0) {
        return $matches | Sort-Object Score -Descending | Select-Object -First 1
    }
    
    return $matches
}

function ExtractKeywords {
    param([string]$Text)
    
    # Remove common words and extract meaningful keywords
    $stopWords = @('the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 
                   'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 
                   'would', 'should', 'could', 'may', 'might', 'must', 'can',
                   'check', 'test', 'verify', 'ensure', 'validate')
    
    $words = $Text -split '\s+' | Where-Object { 
        $_ -and $_.Length -gt 2 -and $_ -notin $stopWords 
    }
    
    return $words
}

function ExtractValues {
    param([string]$Text)
    
    $values = @()
    
    # Extract numbers
    if ($Text -match '\b\d+(\.\d+)?\b') {
        $values += $matches[0]
    }
    
    # Extract quoted strings
    if ($Text -match '"([^"]+)"' -or $Text -match "'([^']+)'") {
        $values += $matches[1]
    }
    
    # Extract boolean values
    if ($Text -match '\b(true|false)\b') {
        $values += $matches[1]
    }
    
    return $values
}

function Get-AssertionMatchReport {
    <#
    .SYNOPSIS
    Generates a detailed report of assertion matching for a test
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Goals,
        
        [Parameter(Mandatory)]
        [hashtable]$AssertionResults,
        
        [switch]$IncludeUnmatched
    )
    
    $report = @{
        Goals = @{}
        UnmatchedAssertions = @()
        MatchQuality = 0
    }
    
    $matchedAssertions = @()
    
    foreach ($goal in $Goals) {
        $matches = Find-AssertionMatch -Goal $goal -AssertionResults $AssertionResults
        $bestMatch = $matches | Sort-Object Score -Descending | Select-Object -First 1
        
        if ($bestMatch) {
            $report.Goals[$goal] = @{
                Matched = $true
                AssertionDescription = $bestMatch.AssertionDescription
                Passed = $AssertionResults[$bestMatch.AssertionDescription]
                MatchType = $bestMatch.MatchType
                Score = $bestMatch.Score
            }
            $matchedAssertions += $bestMatch.AssertionDescription
        } else {
            $report.Goals[$goal] = @{
                Matched = $false
                Passed = $null
            }
        }
    }
    
    # Find unmatched assertions
    if ($IncludeUnmatched) {
        foreach ($assertion in $AssertionResults.Keys) {
            if ($assertion -notin $matchedAssertions) {
                $report.UnmatchedAssertions += @{
                    Description = $assertion
                    Passed = $AssertionResults[$assertion]
                }
            }
        }
    }
    
    # Calculate match quality
    $matchedCount = ($report.Goals.Values | Where-Object { $_.Matched }).Count
    $report.MatchQuality = if ($Goals.Count -gt 0) {
        [Math]::Round(($matchedCount / $Goals.Count) * 100)
    } else { 0 }
    
    return $report
}

function Get-AssertionPerformanceMetrics {
    <#
    .SYNOPSIS
    Analyzes performance metrics from assertion results
    #>
    [CmdletBinding()]
    param(
        [hashtable]$AssertionResults = $Global:LoxoneTestAssertions,
        
        [ValidateSet('All', 'ByTest', 'ByOperator', 'ByStatus')]
        [string]$GroupBy = 'All'
    )
    
    $metrics = @{
        TotalAssertions = 0
        TotalDurationMs = 0
        AverageDurationMs = 0
        MinDurationMs = [double]::MaxValue
        MaxDurationMs = 0
        PassedCount = 0
        FailedCount = 0
        PerformanceByOperator = @{}
        PerformanceByTest = @{}
        SlowAssertions = @()
    }
    
    # Collect all assertions with timing data
    $allAssertions = @()
    foreach ($test in $AssertionResults.Values) {
        foreach ($assertion in $test.Assertions) {
            if ($assertion.DurationMs) {
                $allAssertions += @{
                    TestName = $test.TestName
                    FunctionName = $test.FunctionName
                    Assertion = $assertion
                }
            }
        }
    }
    
    if ($allAssertions.Count -eq 0) {
        Write-Warning "No assertion timing data available"
        return $metrics
    }
    
    # Calculate overall metrics
    $metrics.TotalAssertions = $allAssertions.Count
    $durations = $allAssertions | ForEach-Object { $_.Assertion.DurationMs }
    $metrics.TotalDurationMs = ($durations | Measure-Object -Sum).Sum
    $metrics.AverageDurationMs = ($durations | Measure-Object -Average).Average
    $metrics.MinDurationMs = ($durations | Measure-Object -Minimum).Minimum
    $metrics.MaxDurationMs = ($durations | Measure-Object -Maximum).Maximum
    $metrics.PassedCount = ($allAssertions | Where-Object { $_.Assertion.Passed }).Count
    $metrics.FailedCount = ($allAssertions | Where-Object { -not $_.Assertion.Passed }).Count
    
    # Group by operator
    $operatorGroups = $allAssertions | Group-Object { $_.Assertion.Operator }
    foreach ($group in $operatorGroups) {
        $groupDurations = $group.Group | ForEach-Object { $_.Assertion.DurationMs }
        $metrics.PerformanceByOperator[$group.Name] = @{
            Count = $group.Count
            AverageDurationMs = [Math]::Round(($groupDurations | Measure-Object -Average).Average, 2)
            TotalDurationMs = ($groupDurations | Measure-Object -Sum).Sum
            MinDurationMs = ($groupDurations | Measure-Object -Minimum).Minimum
            MaxDurationMs = ($groupDurations | Measure-Object -Maximum).Maximum
        }
    }
    
    # Group by test
    $testGroups = $allAssertions | Group-Object TestName
    foreach ($group in $testGroups) {
        $groupDurations = $group.Group | ForEach-Object { $_.Assertion.DurationMs }
        $metrics.PerformanceByTest[$group.Name] = @{
            Count = $group.Count
            AverageDurationMs = [Math]::Round(($groupDurations | Measure-Object -Average).Average, 2)
            TotalDurationMs = ($groupDurations | Measure-Object -Sum).Sum
            PassedCount = ($group.Group | Where-Object { $_.Assertion.Passed }).Count
            FailedCount = ($group.Group | Where-Object { -not $_.Assertion.Passed }).Count
        }
    }
    
    # Identify slow assertions (> 100ms or top 10%)
    $threshold = [Math]::Max(100, $metrics.AverageDurationMs * 3)
    $metrics.SlowAssertions = $allAssertions | 
        Where-Object { $_.Assertion.DurationMs -gt $threshold } |
        Sort-Object { $_.Assertion.DurationMs } -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            @{
                TestName = $_.TestName
                Description = $_.Assertion.Description
                DurationMs = $_.Assertion.DurationMs
                Operator = $_.Assertion.Operator
                Passed = $_.Assertion.Passed
            }
        }
    
    return $metrics
}

function Export-AssertionPerformanceReport {
    <#
    .SYNOPSIS
    Exports a detailed performance report for assertions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [hashtable]$Metrics,
        
        [ValidateSet('Markdown', 'HTML', 'JSON')]
        [string]$Format = 'Markdown'
    )
    
    if (-not $Metrics) {
        $Metrics = Get-AssertionPerformanceMetrics
    }
    
    switch ($Format) {
        'Markdown' {
            $report = @"
# Assertion Performance Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Summary
- **Total Assertions:** $($Metrics.TotalAssertions)
- **Total Duration:** $([Math]::Round($Metrics.TotalDurationMs, 2))ms
- **Average Duration:** $([Math]::Round($Metrics.AverageDurationMs, 2))ms
- **Min/Max Duration:** $([Math]::Round($Metrics.MinDurationMs, 2))ms / $([Math]::Round($Metrics.MaxDurationMs, 2))ms
- **Pass Rate:** $([Math]::Round(($Metrics.PassedCount / $Metrics.TotalAssertions) * 100, 1))%

## Performance by Operator
| Operator | Count | Avg Duration | Total Duration |
|----------|-------|--------------|----------------|
"@
            foreach ($op in $Metrics.PerformanceByOperator.Keys | Sort-Object) {
                $opData = $Metrics.PerformanceByOperator[$op]
                $report += "`n| $op | $($opData.Count) | $($opData.AverageDurationMs)ms | $($opData.TotalDurationMs)ms |"
            }
            
            if ($Metrics.SlowAssertions.Count -gt 0) {
                $report += @"

## Slowest Assertions
| Test | Description | Duration | Status |
|------|-------------|----------|--------|
"@
                foreach ($slow in $Metrics.SlowAssertions) {
                    $status = if ($slow.Passed) { "Passed" } else { "Failed" }
                    $report += "`n| $($slow.TestName) | $($slow.Description) | $($slow.DurationMs)ms | $status |"
                }
            }
            
            $report | Out-File -FilePath $Path -Encoding UTF8
        }
        
        'HTML' {
            # HTML report generation would go here
            Write-Warning "HTML format not yet implemented"
        }
        
        'JSON' {
            $Metrics | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Enable-AssertionTracking'
    'Disable-AssertionTracking'
    'Set-TestContext'
    'Get-TestAssertionResults'
    'Export-TestAssertionResults'
    'Get-CachedAssertionResults'
    'Set-CachedAssertionResults'
    'Import-AssertionResults'
    'Merge-AssertionResults'
    'Find-AssertionMatch'
    'Get-AssertionMatchReport'
    'Get-AssertionPerformanceMetrics'
    'Export-AssertionPerformanceReport'
)