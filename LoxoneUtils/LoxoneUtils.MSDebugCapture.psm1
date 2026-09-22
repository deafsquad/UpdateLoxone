#Requires -Version 5.1
<#
.SYNOPSIS
    Miniserver debug-stream capture for update runs.

.DESCRIPTION
    Captures the Miniserver's UDP debug stream (GET /dev/sps/log/<ip> makes the MS send it to
    <ip>:7777) for ALL Miniservers of a run into ONE file, every line tagged with the sending
    Miniserver's IP. Also drives the persisted "extended logging" flag /dev/cfg/loglevel (a
    boolean: 0/1, anything else is clamped to 0 by the firmware; self-expires after 14 days).

    Verified live 2026-09-02 on e1 (192.168.2.210, fw 17.2.8.28): flag 1 doubles the rate and
    adds subsystems absent at 0 ("OTAU check", "mDNS request", "CUDPsocket::ReceiveFrom",
    "MS #Send"). Both endpoints need a user holding the debug-log right: the plain 'update'
    user answers Code 403 on both until that right is granted in Loxone Config.

    The stream enable does NOT survive the Miniserver restart: re-arm it once the MS answers
    HTTP again after the update. ALWAYS disable it in a finally so the MS never keeps sending
    to a dead listener.

    Datagram layout (empirical): 29-byte binary header + NUL-terminated ASCII, several records
    per datagram. Decode = printable runs of >= 8 chars, the same approach loxq uses.
#>

$script:MSDebugPrintableRunRegex = [regex]'[\x20-\x7e\t]{8,}'

#region Local helpers
function Get-MSDebugListenerIP {
    <# .SYNOPSIS Local IPv4 the given Miniserver can reach (the address of the route toward it). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TargetHost)
    $probe = $null
    try {
        $probe = New-Object System.Net.Sockets.UdpClient
        $probe.Connect($TargetHost, 80)
        return $probe.Client.LocalEndPoint.Address.ToString()
    } catch {
        Write-Log -Level WARN -Message "(Get-MSDebugListenerIP) Could not determine route IP toward ${TargetHost}: $($_.Exception.Message)"
        return $null
    } finally { if ($probe) { $probe.Close() } }
}

function ConvertTo-MSDebugLines {
    <# .SYNOPSIS Decode one datagram into printable text runs (>= 8 chars). Pure; unit-tested. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Datagram)
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString($Datagram)   # Latin-1: 1 byte = 1 char
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:MSDebugPrintableRunRegex.Matches($text)) { $out.Add($m.Value.Trim()) }
    return ,$out.ToArray()
}

function Invoke-MSDebugApi {
    <# .SYNOPSIS GET a /dev/... path with basic auth; returns Http, Code (XML), Value, Body. Never throws. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme,
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter()][string]$UserName,
        [Parameter()]$Password,            # plain string or SecureString
        [Parameter()][switch]$SkipCertificateCheck,
        [Parameter()][int]$TimeoutSec = 8
    )
    $plain = $null
    if ($Password -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        try { $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    } elseif ($null -ne $Password) { $plain = [string]$Password }
    $params = @{ Uri = "${Scheme}://${HostName}${Path}"; UseBasicParsing = $true; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($UserName) {
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${UserName}:${plain}"))
        $params.Headers = @{ Authorization = "Basic $b64" }
    }
    if ($SkipCertificateCheck -and $Scheme -eq 'https' -and $PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
    $result = [pscustomobject]@{ Http = -1; Code = $null; Value = $null; Body = $null }
    try {
        $r = Invoke-WebRequest @params
        $result.Http = [int]$r.StatusCode
        $result.Body = ($r.Content -replace '\s+', ' ').Trim()
    } catch {
        try { $result.Http = [int]$_.Exception.Response.StatusCode } catch { }
        $result.Body = $_.Exception.Message
    }
    if ($result.Body -match 'Code="(\d+)"') { $result.Code = [int]$matches[1] }
    if ($result.Body -match 'value="([^"]*)"') { $result.Value = $matches[1] }
    return $result
}
#endregion

#region Stream on/off + extended-logging flag
function Get-MSDebugRightHint {
    <# .SYNOPSIS The one-line fix for a Code 403: the right lives on the 'LOXONE Config' permission of the user. #>
    param([Parameter()][string]$UserName = 'update')
    "grant 'LOXONE Config' to user '$UserName' in Loxone Config (loxq: loxq grant $UserName `"LOXONE Config`")"
}

function Request-MSDebugStream {
    <#
    .SYNOPSIS GET /dev/sps/log/<ListenerIP> and say WHY it did or did not take.
    .OUTPUTS  [pscustomobject] Enabled (bool), Code (XML Code or $null), Http, Reason (text for a person; $null when enabled).
              Code 403 = the user lacks the debug-log right, which comes with the 'LOXONE Config' permission.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$ListenerIP,
        [Parameter()][string]$UserName, [Parameter()]$Password, [Parameter()][switch]$SkipCertificateCheck
    )
    $r = Invoke-MSDebugApi -Scheme $Scheme -HostName $HostName -Path "/dev/sps/log/$ListenerIP" -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck
    $out = [pscustomobject]@{ Enabled = $false; Code = $r.Code; Http = $r.Http; Reason = $null }
    if ($r.Http -eq 200 -and $r.Code -eq 200) {
        Write-Log -Level INFO -Message "[MSDEBUG] $HostName debug stream enabled -> ${ListenerIP}:7777"
        $out.Enabled = $true
        return $out
    }
    if ($r.Code -eq 403) {
        $out.Reason = "Code 403: user '$UserName' lacks the debug-log right - $(Get-MSDebugRightHint -UserName $UserName)"
        Write-Log -Level WARN -Message "[MSDEBUG] $HostName refused the debug stream ($($out.Reason)). Continuing without capture."
    } else {
        $out.Reason = "enable failed (HTTP $($r.Http), Code $($r.Code)): $($r.Body)"
        Write-Log -Level WARN -Message "[MSDEBUG] $HostName debug stream $($out.Reason)"
    }
    return $out
}

function Enable-MSDebugStream {
    <# .SYNOPSIS GET /dev/sps/log/<ListenerIP>. Returns $true on Code 200. Code 403 = user lacks the right. (Bool wrapper of Request-MSDebugStream.) #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][string]$ListenerIP,
        [Parameter()][string]$UserName, [Parameter()]$Password, [Parameter()][switch]$SkipCertificateCheck
    )
    return [bool](Request-MSDebugStream -Scheme $Scheme -HostName $HostName -ListenerIP $ListenerIP -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck).Enabled
}

function Get-MSDebugCaptureSummary {
    <#
    .SYNOPSIS  "MS debug capture covered N of M Miniservers" plus one line per box that was NOT captured, with its reason.
    .DESCRIPTION
        A refused capture must be loud. On 2026-09-22 the 17.3.9.21 upgrade captured ONE of three Miniservers
        (home and e1 answered Code 403) and the only trace was an INFO line at 02:09 - found the next morning,
        after the post-reboot window the operator wanted to read had passed. This turns the per-Miniserver
        outcomes into the text the final summary, the toast and the log carry.
    .PARAMETER Outcomes
        One entry per Miniserver that went through Invoke-MSUpdate: @{ IP; Enabled; Rearmed; Reason }.
    .OUTPUTS  [pscustomobject] Covered, Total, AllCovered, Headline, Lines (Headline + one "<ip>: <reason>" per uncovered box), Text (Lines joined).
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][AllowEmptyCollection()]$Outcomes)
    $all = @($Outcomes | Where-Object { $null -ne $_ })
    $covered = @($all | Where-Object { $_.Enabled -eq $true })
    $missed = @($all | Where-Object { $_.Enabled -ne $true })
    $headline = "MS debug capture covered $($covered.Count) of $($all.Count) Miniservers"
    $lines = @($headline)
    foreach ($m in $missed) {
        $why = if ($m.Reason) { "$($m.Reason)" } else { 'not captured (no reason recorded)' }
        $lines += "  $($m.IP): $why"
    }
    [pscustomobject]@{
        Covered    = $covered.Count
        Total      = $all.Count
        AllCovered = ($missed.Count -eq 0)
        Headline   = $headline
        Lines      = $lines
        Text       = ($lines -join [Environment]::NewLine)
    }
}

function Disable-MSDebugStream {
    <# .SYNOPSIS GET /dev/sps/log (no ip = off). Best effort; returns $true on Code 200. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter()][string]$UserName, [Parameter()]$Password, [Parameter()][switch]$SkipCertificateCheck
    )
    $r = Invoke-MSDebugApi -Scheme $Scheme -HostName $HostName -Path '/dev/sps/log' -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck -TimeoutSec 5
    if ($r.Http -eq 200 -and $r.Code -eq 200) { Write-Log -Level INFO -Message "[MSDEBUG] $HostName debug stream disabled"; return $true }
    Write-Log -Level WARN -Message "[MSDEBUG] $HostName debug stream disable not confirmed (HTTP $($r.Http), Code $($r.Code)) - the setting does not survive a restart anyway"
    return $false
}

function Get-MSExtendedLogging {
    <# .SYNOPSIS Read /dev/cfg/loglevel. Returns 0/1, or $null when unreadable (403, 404, offline). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter()][string]$UserName, [Parameter()]$Password, [Parameter()][switch]$SkipCertificateCheck
    )
    $r = Invoke-MSDebugApi -Scheme $Scheme -HostName $HostName -Path '/dev/cfg/loglevel' -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck
    if ($r.Http -eq 200 -and $r.Code -eq 200 -and $r.Value -match '^\d+$') { return [int]$r.Value }
    Write-Log -Level DEBUG -Message "[MSDEBUG] $HostName /dev/cfg/loglevel not readable (HTTP $($r.Http), Code $($r.Code))"
    return $null
}

function Set-MSExtendedLogging {
    <# .SYNOPSIS Write /dev/cfg/loglevel/<0|1> and verify by read-back. Persisted on the MS (self-expires after 14 days). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Scheme, [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][ValidateRange(0, 1)][int]$Value,
        [Parameter()][string]$UserName, [Parameter()]$Password, [Parameter()][switch]$SkipCertificateCheck
    )
    $null = Invoke-MSDebugApi -Scheme $Scheme -HostName $HostName -Path "/dev/cfg/loglevel/$Value" -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck
    $back = Get-MSExtendedLogging -Scheme $Scheme -HostName $HostName -UserName $UserName -Password $Password -SkipCertificateCheck:$SkipCertificateCheck
    if ($back -eq $Value) { Write-Log -Level INFO -Message "[MSDEBUG] $HostName extended logging set to $Value (verified)"; return $true }
    Write-Log -Level WARN -Message "[MSDEBUG] $HostName extended logging write to $Value NOT verified (read back '$back')"
    return $false
}
#endregion

#region Listener (one per run, all Miniservers)
function Start-MSDebugCapture {
    <#
    .SYNOPSIS  Bind UDP 0.0.0.0:<Port> in a ThreadJob and write decoded lines "[ts] [src-ip] text" to OutputPath.
    .OUTPUTS   Handle hashtable (Job, StopEvent, OutputPath, Port) or $null when the bind fails.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter()][int]$Port = 7777,
        [Parameter()][int]$KeepFiles = 10
    )
    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    # Retention: these files can reach tens of MB per run
    try {
        Get-ChildItem -Path $dir -Filter 'msdebug_*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
            Select-Object -Skip ([Math]::Max(0, $KeepFiles - 1)) | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }

    # Bind here (not in the job) so a port conflict is reported synchronously
    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $Port)))
        $udp.Client.ReceiveTimeout = 1000
    } catch {
        Write-Log -Level WARN -Message "[MSDEBUG] Cannot bind UDP port ${Port}: $($_.Exception.Message) - running WITHOUT Miniserver debug capture"
        if ($udp) { $udp.Close() }
        return $null
    }
    $stopEvent = New-Object System.Threading.ManualResetEventSlim($false)
    $job = Start-ThreadJob -Name 'MSDebugCapture' -ArgumentList $udp, $stopEvent, $OutputPath -ScriptBlock {
        param($udp, $stopEvent, $path)
        $rx = [regex]'[\x20-\x7e\t]{8,}'
        $latin1 = [System.Text.Encoding]::GetEncoding(28591)
        $fh = New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $n = 0; $lines = 0; $lastFlush = [DateTime]::UtcNow
        $fh.WriteLine("# msdebug capture started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - lines: [local-ts] [miniserver-ip] text")
        try {
            while (-not $stopEvent.IsSet) {
                try { $data = $udp.Receive([ref]$ep) } catch { continue }   # 1s receive timeout keeps the stop check alive
                $n++
                $stamp = (Get-Date).ToString('HH:mm:ss.fff')
                foreach ($m in $rx.Matches($latin1.GetString($data))) { $lines++; $fh.WriteLine("[$stamp] [$($ep.Address)] $($m.Value.Trim())") }
                if (([DateTime]::UtcNow - $lastFlush).TotalSeconds -ge 2) { $fh.Flush(); $lastFlush = [DateTime]::UtcNow }
            }
        } finally {
            $fh.WriteLine("# msdebug capture stopped $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - $n datagrams, $lines lines")
            $fh.Flush(); $fh.Close(); $udp.Close()
        }
        "$n datagrams, $lines lines"
    }
    Write-Log -Level INFO -Message "[MSDEBUG] Capture listener on UDP :$Port -> $OutputPath"
    return @{ Job = $job; StopEvent = $stopEvent; OutputPath = $OutputPath; Port = $Port }
}

function Stop-MSDebugCapture {
    <# .SYNOPSIS Signal the listener job to stop, wait for it, and report the totals. Safe to call with $null. #>
    [CmdletBinding()]
    param([Parameter()][hashtable]$Handle)
    if (-not $Handle) { return }
    try {
        $Handle.StopEvent.Set()
        $null = Wait-Job -Job $Handle.Job -Timeout 15
        $summary = (Receive-Job -Job $Handle.Job -ErrorAction SilentlyContinue | Select-Object -Last 1)
        Remove-Job -Job $Handle.Job -Force -ErrorAction SilentlyContinue
        $size = if (Test-Path $Handle.OutputPath) { [Math]::Round((Get-Item $Handle.OutputPath).Length / 1KB) } else { 0 }
        Write-Log -Level INFO -Message "[MSDEBUG] Capture stopped: $summary, $size KB -> $($Handle.OutputPath)"
    } catch {
        Write-Log -Level WARN -Message "[MSDEBUG] Error stopping capture: $($_.Exception.Message)"
    }
}
#endregion

Export-ModuleMember -Function @(
    'Get-MSDebugListenerIP', 'ConvertTo-MSDebugLines', 'Invoke-MSDebugApi',
    'Get-MSDebugRightHint', 'Request-MSDebugStream', 'Enable-MSDebugStream', 'Disable-MSDebugStream',
    'Get-MSDebugCaptureSummary',
    'Get-MSExtendedLogging', 'Set-MSExtendedLogging',
    'Start-MSDebugCapture', 'Stop-MSDebugCapture'
)
