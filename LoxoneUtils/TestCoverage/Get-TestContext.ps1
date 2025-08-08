function Get-TestContext {
    <#
    .SYNOPSIS
        Extracts test context information from test content
    
    .DESCRIPTION
        Parses test file content to extract Describe/Context/It blocks
        that reference a specific function, including test expectations
    #>
    [CmdletBinding()]
    param(
        [string]$TestContent,
        [string]$FunctionName,
        [string]$TestFileName
    )
    
    $contexts = @()
    
    # Find Describe blocks that are specifically for this function
    # Match patterns like:
    # Describe "FunctionName Function" 
    # Describe "FunctionName Core Functionality"
    # Describe "FunctionName"
    $describePatternsForFunction = @(
        "Describe\s+[`"']$FunctionName\s+Function[`"']",
        "Describe\s+[`"']$FunctionName\s+Core\s+Functionality[`"']",
        "Describe\s+[`"']$FunctionName[`"']",
        "Describe\s+[`"']$FunctionName\s+Command[`"']",
        "Describe\s+[`"']$FunctionName\s+Cmdlet[`"']"
    )
    
    $isRelevantDescribeBlock = $false
    $describeTitle = ""
    
    # Check if this file contains a Describe block for our function
    foreach ($pattern in $describePatternsForFunction) {
        if ($TestContent -match $pattern) {
            $isRelevantDescribeBlock = $true
            # Extract the describe title
            if ($TestContent -match "Describe\s+[`"']([^`"']+)[`"'].*?{") {
                $describeTitle = $matches[1]
            }
            break
        }
    }
    
    # Only process if we found a relevant Describe block
    if ($isRelevantDescribeBlock) {
        # Extract the content of the Describe block for this function
        $describeBlockPattern = "Describe\s+[`"'][^`"']*$FunctionName[^`"']*[`"']\s*{[\s\S]*?^}"
        
        # Use a simpler approach - find the Describe block and process its content
        if ($TestContent -match "Describe\s+[`"']([^`"']*$FunctionName[^`"']*)[`"']") {
            $describeStart = $matches.Index
            $blockContent = $TestContent.Substring($describeStart)
            
            # Count braces to find the end of the Describe block
            $braceCount = 0
            $inString = $false
            $escapeNext = $false
            $blockEnd = -1
            
            for ($i = 0; $i -lt $blockContent.Length; $i++) {
                $char = $blockContent[$i]
                
                if ($escapeNext) {
                    $escapeNext = $false
                    continue
                }
                
                if ($char -eq '`') {
                    $escapeNext = $true
                    continue
                }
                
                if ($char -eq '"' -or $char -eq "'") {
                    $inString = -not $inString
                    continue
                }
                
                if (-not $inString) {
                    if ($char -eq '{') {
                        $braceCount++
                    } elseif ($char -eq '}') {
                        $braceCount--
                        if ($braceCount -eq 0) {
                            $blockEnd = $i
                            break
                        }
                    }
                }
            }
            
            if ($blockEnd -gt 0) {
                $relevantContent = $blockContent.Substring(0, $blockEnd + 1)
                
                # Find Context blocks within this Describe block
                $contextPattern = 'Context\s+["'']([^"'']+)["'']'
                $contextMatches = [regex]::Matches($relevantContent, $contextPattern)
                
                # Find It blocks within this Describe block
                $itPattern = 'It\s+["'']([^"'']+)["'']'
                $itMatches = [regex]::Matches($relevantContent, $itPattern)
                
                # Extract test expectations (Should statements)
                $expectationPattern = @(
                    'Should\s+-(\w+)(?:\s+(.+?)(?:\s*[-;]|$))?',
                    '\|\s*Should\s+-(\w+)(?:\s+(.+?)(?:\s*[-;]|$))?'
                )
                
                # Process Context blocks if they exist
                if ($contextMatches.Count -gt 0) {
                    foreach ($contextMatch in $contextMatches) {
                        $contextTitle = $contextMatch.Groups[1].Value
                        $contextStart = $contextMatch.Index
                        
                        # Find It blocks within this Context
                        foreach ($itMatch in $itMatches) {
                            if ($itMatch.Index -gt $contextStart) {
                                $itTitle = $itMatch.Groups[1].Value
                                
                                # Extract expectations for this It block
                                $expectations = @()
                                # Get content after the It block
                                $itEnd = $itMatch.Index + $itMatch.Length
                                $nextItIndex = $relevantContent.Length
                                foreach ($nextIt in $itMatches) {
                                    if ($nextIt.Index -gt $itEnd -and $nextIt.Index -lt $nextItIndex) {
                                        $nextItIndex = $nextIt.Index
                                        break
                                    }
                                }
                                
                                $itContent = $relevantContent.Substring($itEnd, $nextItIndex - $itEnd)
                                foreach ($expPattern in $expectationPattern) {
                                    $expMatches = [regex]::Matches($itContent, $expPattern)
                                    foreach ($expMatch in $expMatches) {
                                        $expectations += @{
                                            Type = $expMatch.Groups[1].Value
                                            Value = if ($expMatch.Groups.Count -gt 2) { $expMatch.Groups[2].Value } else { "" }
                                        }
                                    }
                                }
                                
                                $contexts += @{
                                    Describe = $describeTitle
                                    It = "$contextTitle.$itTitle"
                                    TestFile = $TestFileName
                                    Expectations = $expectations
                                }
                                
                                # Only process It blocks that belong to this Context
                                $nextContextIndex = $relevantContent.Length
                                foreach ($nextContext in $contextMatches) {
                                    if ($nextContext.Index -gt $contextStart) {
                                        $nextContextIndex = $nextContext.Index
                                        break
                                    }
                                }
                                if ($itMatch.Index -ge $nextContextIndex) {
                                    break
                                }
                            }
                        }
                    }
                } else {
                    # No Context blocks, just It blocks directly under Describe
                    foreach ($itMatch in $itMatches) {
                        $itTitle = $itMatch.Groups[1].Value
                        
                        # Extract expectations
                        $expectations = @()
                        $itEnd = $itMatch.Index + $itMatch.Length
                        $nextItIndex = $relevantContent.Length
                        foreach ($nextIt in $itMatches) {
                            if ($nextIt.Index -gt $itEnd) {
                                $nextItIndex = $nextIt.Index
                                break
                            }
                        }
                        
                        $itContent = $relevantContent.Substring($itEnd, [Math]::Min(500, $nextItIndex - $itEnd))
                        foreach ($expPattern in $expectationPattern) {
                            $expMatches = [regex]::Matches($itContent, $expPattern)
                            foreach ($expMatch in $expMatches) {
                                $expectations += @{
                                    Type = $expMatch.Groups[1].Value
                                    Value = if ($expMatch.Groups.Count -gt 2) { $expMatch.Groups[2].Value } else { "" }
                                }
                            }
                        }
                        
                        $contexts += @{
                            Describe = $describeTitle
                            It = $itTitle
                            TestFile = $TestFileName
                            Expectations = $expectations
                        }
                    }
                }
            }
        }
    }
    
    return $contexts
}