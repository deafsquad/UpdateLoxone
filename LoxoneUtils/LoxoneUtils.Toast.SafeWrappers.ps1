# Safe wrapper functions for Toast module
# These handle cases where logging functions aren't available (e.g., in parallel execution contexts)

function Write-SafeLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [switch]$SkipStackFrame
    )
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message $Message -Level $Level -SkipStackFrame:$SkipStackFrame
    } else {
        # Fallback to Write-Verbose when Write-Log isn't available
        Write-Verbose "[$Level] $Message"
    }
}

function Enter-SafeFunction {
    param(
        [string]$FunctionName,
        [string]$FilePath,
        [int]$LineNumber
    )
    
    if (Get-Command Enter-Function -ErrorAction SilentlyContinue) {
        Enter-Function -FunctionName $FunctionName -FilePath $FilePath -LineNumber $LineNumber
    } else {
        Write-Verbose "Entering function: $FunctionName"
    }
}

function Exit-SafeFunction {
    if (Get-Command Exit-Function -ErrorAction SilentlyContinue) {
        Exit-Function
    } else {
        Write-Verbose "Exiting function"
    }
}

# Export wrapper functions
Export-ModuleMember -Function Write-SafeLog, Enter-SafeFunction, Exit-SafeFunction