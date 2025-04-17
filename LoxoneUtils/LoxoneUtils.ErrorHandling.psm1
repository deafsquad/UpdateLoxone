# Module for Loxone Update Script Error Handling Functions

#region Error Handling
function Invoke-ScriptErrorHandling {
    param(
        # The PowerShell ErrorRecord object to handle.
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    Enter-Function -FunctionName $MyInvocation.MyCommand.Name -FilePath $MyInvocation.ScriptName -LineNumber $MyInvocation.ScriptLineNumber
    if (-not $ErrorRecord) { $ErrorRecord = $Error[0] }
    try {
    $invInfo = $ErrorRecord.InvocationInfo
    $command = if ($invInfo -and $invInfo.MyCommand) { $invInfo.MyCommand.ToString() } else { "N/A" }
    $scriptName = if ($invInfo -and $invInfo.ScriptName) { $invInfo.ScriptName } else { "N/A" }
    $lineNumber = if ($invInfo -and $invInfo.ScriptLineNumber) { $invInfo.ScriptLineNumber } else { "N/A" }
    $line = if ($invInfo -and $invInfo.Line) { $invInfo.Line } else { "N/A" }
    $position = if ($invInfo -and $invInfo.PositionMessage) { $invInfo.PositionMessage } else { "N/A" }
    $fullCommandLine = if ($line) { $line.Trim() } else { "N/A" }
    $localVars = Get-Variable -Scope 1 | ForEach-Object { "$($_.Name) = $($_.Value)" } | Out-String

    Write-Log -Message "ERROR in command: ${command}" -Level ERROR
    Write-Log -Message "Script: ${scriptName}" -Level ERROR
    Write-Log -Message "Line number: ${lineNumber}" -Level ERROR
    Write-Log -Message "Offending line: ${line}" -Level ERROR
    Write-Log -Message "Position details: ${position}" -Level ERROR
    Write-Log -Message "Full command line: ${fullCommandLine}" -Level ERROR
    Write-Log -Message "Local variables in scope:`n${localVars}" -Level ERROR

    Update-PersistentToast -NewStatus "FAILED: $($ErrorRecord.Exception.Message) (Cmd: $command, Line: $lineNumber)"

    # Log comprehensive error details
    Write-Log -Message "-------------------- SCRIPT ERROR DETAILS --------------------" -Level ERROR
    Write-Log -Message "Full Error Record: $($ErrorRecord.ToString())" -Level ERROR
    Write-Log -Message "Exception Message: ${($ErrorRecord.Exception.Message)}" -Level ERROR

    if ($invInfo) {
        Write-Log -Message "Occurred in Command: ${command}" -Level ERROR
        Write-Log -Message "Script: ${scriptName}" -Level ERROR
        Write-Log -Message "Line Number: ${lineNumber}" -Level ERROR
        Write-Log -Message "Offending Line Content: ${line}" -Level ERROR
        Write-Log -Message "Position Details: ${position}" -Level ERROR
        Write-Log -Message "Full Command Line Parsed: ${fullCommandLine}" -Level ERROR
    } else {
        Write-Log -Message "InvocationInfo not available." -Level ERROR
    }

    Write-Log -Message "Local Variables in Caller Scope:`n${localVars}" -Level ERROR

    # Log PowerShell Script Stack Trace
    if ($ErrorRecord.ScriptStackTrace) {
        Write-Log -Message "PowerShell Script Stack Trace:`n${($ErrorRecord.ScriptStackTrace)}" -Level ERROR
    } else {
        Write-Log -Message "No PowerShell Script Stack Trace available." -Level ERROR
    }

    # Log .NET Exception Stack Trace (if available)
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.StackTrace) {
        Write-Log -Message ".NET Exception Stack Trace:`n${($ErrorRecord.Exception.StackTrace)}" -Level ERROR
    } else {
        Write-Log -Message "No .NET Exception Stack Trace available." -Level ERROR
    }
    Write-Log -Message "------------------ END SCRIPT ERROR DETAILS ------------------" -Level ERROR

	# ASSUMPTION: $global:ErrorOccurred and $global:LastErrorLine are set globally by the calling script/environment
	$global:ErrorOccurred = $true
    $global:LastErrorLine = $lineNumber

    Write-Log -Message "Script error occurred on line $global:LastErrorLine. Error flag set." -Level ERROR
    # Removed exit 1 - Let the caller handle termination/pausing
    } finally {
        Exit-Function
    }
}
#endregion Error Handling

# Ensure functions are available (though NestedModules in PSD1 is the primary mechanism)
# Export-ModuleMember -Function Invoke-ScriptErrorHandling # Commented out: Exports must be handled ONLY by the PSD1 manifest when using RootModule
# NOTE: Explicit Export-ModuleMember is required for the manifest to re-export with FunctionsToExport = '*'.