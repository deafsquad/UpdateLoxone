# Structural syntax invariants for all project scripts.
# Regression (2026-07-03): a misplaced '} catch {' inside Invoke-MSUpdate closed the function's
# main try early, leaving the real 'catch {...} finally {...}' at the end DETACHED. Detached
# try/catch/finally keywords parse as ordinary COMMANDS (no parse error!) and only explode at
# runtime with "The term 'catch' is not recognized..." - and only on the code path that reaches
# them (here: the trigger-failed path, first hit when a MS answered 'Update already downloading').
# The AST scan below catches any such detached keyword in ANY project script at test time.
BeforeDiscovery {
    $script:ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ScriptFiles = @(
        Get-ChildItem -Path (Join-Path $script:ProjectRoot 'LoxoneUtils') -Filter '*.psm1' -File
        Get-Item -Path (Join-Path $script:ProjectRoot 'UpdateLoxone.ps1')
    ) | ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } }
}

Describe 'Script syntax invariants' -Tag 'Unit' {
    It '<Name> parses without errors and has no detached try/catch/finally keywords' -ForEach $script:ScriptFiles {
        $tokens = $null; $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($FullName, [ref]$tokens, [ref]$parseErrors)

        $errorText = ($parseErrors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; '
        $parseErrors.Count | Should -Be 0 -Because "parse errors found: $errorText"

        # A 'catch'/'finally'/'try' parsed as a CommandAst means the keyword got detached from its
        # statement (usually by a brace miscount) - valid to the parser, fatal at runtime.
        $strays = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -in @('try', 'catch', 'finally')
        }, $true)
        $strayText = ($strays | ForEach-Object { "'$($_.GetCommandName())' at line $($_.Extent.StartLineNumber)" }) -join '; '
        $strays.Count | Should -Be 0 -Because "detached keywords parse as commands and fail at runtime: $strayText"
    }
}
