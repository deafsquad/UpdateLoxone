#Requires -Version 5.1

<#
.SYNOPSIS
    Loxone Monitor Integration Module

.DESCRIPTION
    Verwaltet loxonemonitor.exe für Miniserver Debug-Logging während Updates.

    Features:
    - Automatische Discovery von .lxmon Speicherorten
    - API-Integration: /dev/sps/log/<ip> (start), /dev/sps/log (stop)
    - Multi-Miniserver Support
    - User- und SYSTEM-Context kompatibel

.NOTES
    Author: UpdateLoxone Project
    Version: 1.0.0
#>

#region Find-LoxoneMonitorExe
function Find-LoxoneMonitorExe {
    <#
    .SYNOPSIS
        Findet loxonemonitor.exe in Loxone Config Installation

    .PARAMETER LoxoneConfigInstallPath
        Wurzelverzeichnis der Loxone Config Installation

    .OUTPUTS
        String - Vollständiger Pfad zu loxonemonitor.exe oder $null
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LoxoneConfigInstallPath
    )

    $FunctionName = "Find-LoxoneMonitorExe"

    if (-not (Test-Path $LoxoneConfigInstallPath)) {
        Write-Log -Message "($FunctionName) Installations-Pfad existiert nicht: $LoxoneConfigInstallPath" -Level ERROR
        return $null
    }

    Write-Log -Message "($FunctionName) Suche loxonemonitor.exe in: $LoxoneConfigInstallPath" -Level DEBUG

    try {
        $monitorExe = Get-ChildItem -Path $LoxoneConfigInstallPath -Filter "loxonemonitor.exe" -Recurse -ErrorAction Stop |
                      Select-Object -First 1

        if ($monitorExe) {
            Write-Log -Message "($FunctionName) ✓ Monitor gefunden: $($monitorExe.FullName)" -Level INFO
            return $monitorExe.FullName
        }
        else {
            Write-Log -Message "($FunctionName) ✗ loxonemonitor.exe nicht gefunden" -Level WARN
            return $null
        }
    }
    catch {
        Write-Log -Message "($FunctionName) Fehler bei Suche: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}
#endregion

#region Start-LoxoneMonitorProcess
function Start-LoxoneMonitorProcess {
    <#
    .SYNOPSIS
        Startet loxonemonitor.exe Prozess

    .PARAMETER MonitorExePath
        Pfad zur loxonemonitor.exe in Loxone Config Installation

    .PARAMETER WorkingDirectory
        Arbeitsverzeichnis (monitor.exe + DLLs werden hierhin kopiert)

    .OUTPUTS
        System.Diagnostics.Process - Gestarteter Prozess oder existierender Prozess
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonitorExePath,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $FunctionName = "Start-LoxoneMonitorProcess"

    # Prüfe ob bereits läuft
    $existing = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log -Message "($FunctionName) Monitor läuft bereits (PID: $($existing.Id))" -Level WARN
        return $existing
    }

    if (-not (Test-Path $MonitorExePath)) {
        Write-Log -Message "($FunctionName) ✗ Monitor.exe nicht gefunden: $MonitorExePath" -Level ERROR
        throw "loxonemonitor.exe nicht gefunden: $MonitorExePath"
    }

    # Erstelle Working Directory falls nicht vorhanden
    if (-not (Test-Path $WorkingDirectory)) {
        New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
        Write-Log -Message "($FunctionName) Working Directory erstellt: $WorkingDirectory" -Level DEBUG
    }

    try {
        # Kopiere monitor.exe
        $targetPath = Join-Path $WorkingDirectory "loxonemonitor.exe"
        Copy-Item -Path $MonitorExePath -Destination $targetPath -Force -ErrorAction Stop
        Write-Log -Message "($FunctionName) Monitor.exe kopiert nach: $targetPath" -Level DEBUG

        # Kopiere DLLs (LoxoneConfigres_*.dll)
        $sourceDir = Split-Path $MonitorExePath -Parent
        $dllPattern = Join-Path $sourceDir "LoxoneConfigres_*.dll"
        $dlls = Get-Item $dllPattern -ErrorAction SilentlyContinue

        if ($dlls) {
            Copy-Item -Path $dllPattern -Destination $WorkingDirectory -Force -ErrorAction Stop
            Write-Log -Message "($FunctionName) $($dlls.Count) DLL(s) kopiert" -Level DEBUG
        }
        else {
            Write-Log -Message "($FunctionName) Keine LoxoneConfigres_*.dll gefunden (ggf. nicht erforderlich)" -Level DEBUG
        }

        # Starte Prozess
        $proc = Start-Process -FilePath $targetPath -WorkingDirectory $WorkingDirectory -PassThru -ErrorAction Stop
        Write-Log -Message "($FunctionName) ✓ Monitor gestartet (PID: $($proc.Id))" -Level INFO

        # Kurz warten bis Prozess initialisiert
        Start-Sleep -Seconds 2

        return $proc
    }
    catch {
        Write-Log -Message "($FunctionName) ✗ Fehler beim Starten: $($_.Exception.Message)" -Level ERROR
        throw
    }
}
#endregion

#region Stop-LoxoneMonitorProcess
function Stop-LoxoneMonitorProcess {
    <#
    .SYNOPSIS
        Stoppt laufenden loxonemonitor.exe Prozess
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Stop-LoxoneMonitorProcess"

    $proc = Get-Process -Name "loxonemonitor" -ErrorAction SilentlyContinue

    if ($proc) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Log -Message "($FunctionName) ✓ Monitor gestoppt (PID: $($proc.Id))" -Level INFO
        }
        catch {
            Write-Log -Message "($FunctionName) Fehler beim Stoppen: $($_.Exception.Message)" -Level WARN
        }
    }
    else {
        Write-Log -Message "($FunctionName) Monitor läuft nicht" -Level DEBUG
    }
}
#endregion

#region Enable-MiniserverLogging
function Enable-MiniserverLogging {
    <#
    .SYNOPSIS
        Aktiviert Debug-Logging auf Miniserver

    .DESCRIPTION
        API-Aufruf: GET /dev/sps/log/<ip>
        Miniserver sendet danach UDP Debug-Logs an angegebene IP

    .PARAMETER MiniserverUrl
        Miniserver URL mit Credentials (z.B. https://admin:pass@192.168.1.77)

    .PARAMETER TargetIP
        IP-Adresse wohin der Miniserver Logs senden soll (Update-PC IP)

    .OUTPUTS
        Boolean - $true bei Erfolg, $false bei Fehler
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MiniserverUrl,

        [Parameter(Mandatory = $true)]
        [string]$TargetIP
    )

    $FunctionName = "Enable-MiniserverLogging"

    try {
        # Baue URL: /dev/sps/log/<ip>
        $uriBuilder = [System.UriBuilder]$MiniserverUrl
        $uriBuilder.Path = "/dev/sps/log/$TargetIP"
        $logUrl = $uriBuilder.Uri.ToString()

        # Redacted Log für Security
        $redactedUrl = $logUrl -replace '://[^@]+@', '://***:***@'
        Write-Log -Message "($FunctionName) Aktiviere MS-Logging: $redactedUrl" -Level INFO

        $response = Invoke-WebRequest -Uri $logUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            Write-Log -Message "($FunctionName) ✓ MS-Logging aktiviert für IP: $TargetIP" -Level INFO
            return $true
        }
        else {
            Write-Log -Message "($FunctionName) Unerwartete Antwort: StatusCode $($response.StatusCode)" -Level WARN
            return $false
        }
    }
    catch {
        Write-Log -Message "($FunctionName) ✗ Fehler beim Aktivieren: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}
#endregion

#region Disable-MiniserverLogging
function Disable-MiniserverLogging {
    <#
    .SYNOPSIS
        Deaktiviert Debug-Logging auf Miniserver

    .DESCRIPTION
        API-Aufruf: GET /dev/sps/log (ohne IP = deaktivieren)

    .PARAMETER MiniserverUrl
        Miniserver URL mit Credentials (z.B. https://admin:pass@192.168.1.77)

    .OUTPUTS
        Boolean - $true bei Erfolg, $false bei Fehler
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MiniserverUrl
    )

    $FunctionName = "Disable-MiniserverLogging"

    try {
        # Baue URL: /dev/sps/log (ohne IP-Parameter)
        $uriBuilder = [System.UriBuilder]$MiniserverUrl
        $uriBuilder.Path = "/dev/sps/log"
        $logUrl = $uriBuilder.Uri.ToString()

        $redactedUrl = $logUrl -replace '://[^@]+@', '://***:***@'
        Write-Log -Message "($FunctionName) Deaktiviere MS-Logging: $redactedUrl" -Level INFO

        $response = Invoke-WebRequest -Uri $logUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            Write-Log -Message "($FunctionName) ✓ MS-Logging deaktiviert" -Level INFO
            return $true
        }
        else {
            Write-Log -Message "($FunctionName) Unerwartete Antwort: StatusCode $($response.StatusCode)" -Level WARN
            return $false
        }
    }
    catch {
        Write-Log -Message "($FunctionName) ✗ Fehler beim Deaktivieren: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}
#endregion

#region Get-LocalIPAddress
function Get-LocalIPAddress {
    <#
    .SYNOPSIS
        Ermittelt lokale IP-Adresse für Miniserver-Logging

    .DESCRIPTION
        Bevorzugt: Nicht-Loopback IPv4 mit manueller Konfiguration (Static IP)
        Fallback: Erste Nicht-Loopback IPv4

    .OUTPUTS
        String - IP-Adresse
    #>
    [CmdletBinding()]
    param()

    $FunctionName = "Get-LocalIPAddress"

    try {
        # Bevorzugt: Manuell konfigurierte IPv4 (nicht DHCP, nicht Loopback)
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object {
                        $_.IPAddress -ne '127.0.0.1' -and
                        $_.PrefixOrigin -eq 'Manual'
                    }

        if ($adapters) {
            $ip = $adapters[0].IPAddress
            Write-Log -Message "($FunctionName) Gefundene IP (Manual): $ip" -Level DEBUG
            return $ip
        }

        # Fallback: Erste Nicht-Loopback IPv4
        $fallback = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                    Select-Object -First 1

        if ($fallback) {
            $ip = $fallback.IPAddress
            Write-Log -Message "($FunctionName) Gefundene IP (Fallback): $ip" -Level DEBUG
            return $ip
        }

        # Letzte Chance: Loopback
        Write-Log -Message "($FunctionName) ⚠ Keine Nicht-Loopback IP gefunden, verwende 127.0.0.1" -Level WARN
        return "127.0.0.1"
    }
    catch {
        Write-Log -Message "($FunctionName) Fehler bei IP-Ermittlung: $($_.Exception.Message)" -Level ERROR
        return "127.0.0.1"
    }
}
#endregion

#region Find-LxmonFiles
function Find-LxmonFiles {
    <#
    .SYNOPSIS
        Findet .lxmon Speicherort basierend auf Monitor-Prozess Session-ID

    .DESCRIPTION
        Durchsucht bekannte Speicherorte für .lxmon Dateien:
        - User-Context: %USERPROFILE%\Documents\Loxone\...
        - SYSTEM-Context: C:\Windows\Temp, C:\Windows\SysWOW64\config\systemprofile\...

        Mit -DiscoveryMode: Erweiterte rekursive Suche

    .PARAMETER MonitorProcessId
        Process-ID des laufenden loxonemonitor.exe

    .PARAMETER DiscoveryMode
        Aktiviert erweiterte Suche in allen potentiellen Verzeichnissen

    .OUTPUTS
        String - Pfad zum .lxmon Verzeichnis oder $null
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MonitorProcessId,

        [Parameter()]
        [switch]$DiscoveryMode
    )

    $FunctionName = "Find-LxmonFiles"
    $foundPaths = @()

    # 1. Bestimme Session-ID für kontextabhängige Pfade
    try {
        $processCim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $MonitorProcessId" -ErrorAction Stop
        $sessionId = $processCim.SessionId

        Write-Log -Message "($FunctionName) Monitor-Prozess Session-ID: $sessionId" -Level DEBUG

        if ($sessionId -eq 0) {
            # SYSTEM-Context
            $searchPaths = @(
                "C:\Windows\Temp\Loxone",
                "C:\Windows\Temp",
                "C:\Windows\SysWOW64\config\systemprofile\Documents\Loxone\Loxone Config\Monitor",
                "C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Temp\Loxone",
                "C:\Temp\Loxone"
            )
            Write-Log -Message "($FunctionName) SYSTEM-Context erkannt, verwende SYSTEM-Pfade" -Level DEBUG
        }
        else {
            # User-Context
            $userDocs = [Environment]::GetFolderPath('MyDocuments')
            $userAppData = [Environment]::GetFolderPath('LocalApplicationData')
            $searchPaths = @(
                "$userDocs\Loxone\Loxone Config\Monitor",
                "$userAppData\Temp\Loxone",
                "$env:TEMP\Loxone"
            )
            Write-Log -Message "($FunctionName) User-Context erkannt (Session $sessionId), verwende User-Pfade" -Level DEBUG
        }
    }
    catch {
        Write-Log -Message "($FunctionName) Fehler bei Session-ID Ermittlung: $($_.Exception.Message)" -Level WARN
        # Fallback: Beide Pfad-Sets durchsuchen
        $searchPaths = @(
            "$env:TEMP\Loxone",
            "C:\Windows\Temp\Loxone",
            "$([Environment]::GetFolderPath('MyDocuments'))\Loxone\Loxone Config\Monitor"
        )
    }

    # 2. Durchsuche Standard-Pfade
    Write-Log -Message "($FunctionName) Durchsuche $($searchPaths.Count) Standard-Pfade..." -Level DEBUG

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $lxmonFiles = Get-ChildItem -Path $path -Filter "*.lxmon" -File -ErrorAction SilentlyContinue

            if ($lxmonFiles) {
                Write-Log -Message "($FunctionName) ✓ .lxmon Dateien gefunden in: $path ($($lxmonFiles.Count) Datei(en))" -Level INFO
                $foundPaths += $path
            }
            else {
                Write-Log -Message "($FunctionName) Pfad existiert, aber keine .lxmon: $path" -Level DEBUG
            }
        }
        else {
            Write-Log -Message "($FunctionName) Pfad existiert nicht: $path" -Level DEBUG
        }
    }

    # 3. Discovery-Modus: Erweiterte Suche
    if ($DiscoveryMode -and $foundPaths.Count -eq 0) {
        Write-Log -Message "($FunctionName) ═══════════════════════════════════════" -Level INFO
        Write-Log -Message "($FunctionName) DISCOVERY-MODUS: Erweiterte Suche..." -Level INFO
        Write-Log -Message "($FunctionName) ═══════════════════════════════════════" -Level INFO

        # Durchsuche C:\Windows\Temp rekursiv (max Tiefe 2)
        if (Test-Path "C:\Windows\Temp") {
            Write-Log -Message "($FunctionName) [Discovery] Durchsuche C:\Windows\Temp (rekursiv)..." -Level INFO
            try {
                $windowsTemp = Get-ChildItem -Path "C:\Windows\Temp" -Filter "*.lxmon" -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
                foreach ($file in $windowsTemp) {
                    $dir = $file.DirectoryName
                    Write-Log -Message "($FunctionName) [Discovery] ✓ Gefunden: $dir\$($file.Name)" -Level INFO
                    if ($dir -notin $foundPaths) {
                        $foundPaths += $dir
                    }
                }
            }
            catch {
                Write-Log -Message "($FunctionName) [Discovery] Fehler bei C:\Windows\Temp: $_" -Level WARN
            }
        }

        # Durchsuche User-Temp rekursiv
        if (Test-Path $env:TEMP) {
            Write-Log -Message "($FunctionName) [Discovery] Durchsuche $env:TEMP (rekursiv)..." -Level INFO
            try {
                $userTempSearch = Get-ChildItem -Path $env:TEMP -Filter "*.lxmon" -File -Recurse -Depth 2 -ErrorAction SilentlyContinue
                foreach ($file in $userTempSearch) {
                    $dir = $file.DirectoryName
                    Write-Log -Message "($FunctionName) [Discovery] ✓ Gefunden: $dir\$($file.Name)" -Level INFO
                    if ($dir -notin $foundPaths) {
                        $foundPaths += $dir
                    }
                }
            }
            catch {
                Write-Log -Message "($FunctionName) [Discovery] Fehler bei $env:TEMP : $_" -Level WARN
            }
        }

        # Durchsuche User Documents
        $userDocs = [Environment]::GetFolderPath('MyDocuments')
        if (Test-Path $userDocs) {
            Write-Log -Message "($FunctionName) [Discovery] Durchsuche $userDocs\Loxone (rekursiv)..." -Level INFO
            $loxoneDir = Join-Path $userDocs "Loxone"
            if (Test-Path $loxoneDir) {
                try {
                    $docsSearch = Get-ChildItem -Path $loxoneDir -Filter "*.lxmon" -File -Recurse -Depth 3 -ErrorAction SilentlyContinue
                    foreach ($file in $docsSearch) {
                        $dir = $file.DirectoryName
                        Write-Log -Message "($FunctionName) [Discovery] ✓ Gefunden: $dir\$($file.Name)" -Level INFO
                        if ($dir -notin $foundPaths) {
                            $foundPaths += $dir
                        }
                    }
                }
                catch {
                    Write-Log -Message "($FunctionName) [Discovery] Fehler bei Loxone Docs: $_" -Level WARN
                }
            }
        }
    }

    # 4. Ergebnis
    if ($foundPaths.Count -eq 0) {
        Write-Log -Message "($FunctionName) ✗✗✗ KEINE .lxmon Dateien gefunden!" -Level WARN
        Write-Log -Message "($FunctionName) Durchsuchte Standard-Pfade:" -Level INFO
        foreach ($path in $searchPaths) {
            Write-Log -Message "($FunctionName)   - $path" -Level INFO
        }

        if ($DiscoveryMode) {
            Write-Log -Message "($FunctionName) Discovery-Modus war aktiv, aber keine Dateien gefunden" -Level WARN
            Write-Log -Message "($FunctionName) Bitte manuell im Dateisystem suchen und Path melden" -Level INFO
        }
        else {
            Write-Log -Message "($FunctionName) Tipp: Verwende -DiscoveryMode für erweiterte Suche" -Level INFO
        }

        return $null
    }

    # Eindeutige Pfade
    $uniquePaths = $foundPaths | Select-Object -Unique
    $selectedPath = $uniquePaths[0]

    if ($uniquePaths.Count -gt 1) {
        Write-Log -Message "($FunctionName) Mehrere .lxmon Verzeichnisse gefunden:" -Level INFO
        foreach ($path in $uniquePaths) {
            Write-Log -Message "($FunctionName)   - $path" -Level INFO
        }
        Write-Log -Message "($FunctionName) Verwende: $selectedPath" -Level INFO
    }
    else {
        Write-Log -Message "($FunctionName) ✓ .lxmon Verzeichnis: $selectedPath" -Level INFO
    }

    return $selectedPath
}
#endregion

#region Watch-MonitorLogs
function Watch-MonitorLogs {
    <#
    .SYNOPSIS
        Überwacht .lxmon Verzeichnis und verschiebt neue Logs

    .PARAMETER MonitorProcessId
        Process-ID des laufenden Monitors (für Pfad-Discovery)

    .PARAMETER DestinationLogDir
        Zielverzeichnis für .lxmon Dateien

    .PARAMETER MiniserverName
        Name des Miniservers (für Log-Benennung)

    .PARAMETER MaxWaitMinutes
        Maximale Wartezeit in Minuten (Grace Period)

    .PARAMETER UpdateCompletedFlag
        Referenz auf shared Boolean (Update-Completion Signal)

    .PARAMETER DiscoveryMode
        Aktiviert erweiterte Pfad-Suche

    .OUTPUTS
        Boolean - $true wenn Logs erhalten wurden, $false bei Timeout
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$MonitorProcessId,

        [Parameter(Mandatory = $true)]
        [string]$DestinationLogDir,

        [Parameter(Mandatory = $true)]
        [string]$MiniserverName,

        [Parameter()]
        [int]$MaxWaitMinutes = 5,

        [Parameter(Mandatory = $true)]
        [ref]$UpdateCompletedFlag,

        [Parameter()]
        [switch]$DiscoveryMode
    )

    $FunctionName = "Watch-MonitorLogs"

    # Erstelle Zielverzeichnis
    if (-not (Test-Path $DestinationLogDir)) {
        New-Item -ItemType Directory -Path $DestinationLogDir -Force | Out-Null
        Write-Log -Message "($FunctionName) Zielverzeichnis erstellt: $DestinationLogDir" -Level DEBUG
    }

    Write-Log -Message "($FunctionName) Starte .lxmon Überwachung für MS '$MiniserverName'" -Level INFO
    Write-Log -Message "($FunctionName) Max. Wartezeit: $MaxWaitMinutes Minuten" -Level INFO

    # Discovery: Finde .lxmon Speicherort
    $sourceLogDir = Find-LxmonFiles -MonitorProcessId $MonitorProcessId -DiscoveryMode:$DiscoveryMode

    if (-not $sourceLogDir) {
        Write-Log -Message "($FunctionName) ✗ Konnte .lxmon Speicherort nicht finden!" -Level ERROR
        return $false
    }

    Write-Log -Message "($FunctionName) ✓ Überwache Quelle: $sourceLogDir" -Level INFO

    $watchStartTime = Get-Date
    $timeout = New-TimeSpan -Minutes $MaxWaitMinutes
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $logsReceived = $false

    while ($stopwatch.Elapsed -lt $timeout) {
        # Status-Update
        if ($UpdateCompletedFlag.Value -eq $true -and -not $logsReceived) {
            Write-Log -Message "($FunctionName) Update abgeschlossen, warte auf finale .lxmon Logs..." -Level INFO
        }

        try {
            # Suche neue/aktualisierte .lxmon Dateien
            $lxmonFiles = Get-ChildItem -Path $sourceLogDir -Filter "*.lxmon" -ErrorAction SilentlyContinue |
                          Where-Object { $_.LastWriteTime -ge $watchStartTime }

            if ($lxmonFiles) {
                Write-Log -Message "($FunctionName) Neue .lxmon Dateien erkannt: $($lxmonFiles.Count)" -Level INFO

                foreach ($lxmon in $lxmonFiles) {
                    # Timestamp für eindeutige Benennung
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    $newName = "monitor_${MiniserverName}_${timestamp}.lxmon"
                    $destPath = Join-Path $DestinationLogDir $newName

                    try {
                        # Kopiere und lösche Original
                        Copy-Item -Path $lxmon.FullName -Destination $destPath -Force -ErrorAction Stop
                        Remove-Item -Path $lxmon.FullName -Force -ErrorAction Stop

                        Write-Log -Message "($FunctionName) ✓ Log verschoben: $destPath" -Level INFO
                        Write-Log -Message "Monitor-Log für MS '$MiniserverName': $destPath (Format: .lxmon, nur mit loxonemonitor.exe lesbar)" -Level INFO

                        $logsReceived = $true
                    }
                    catch {
                        Write-Log -Message "($FunctionName) Fehler beim Verschieben von $($lxmon.Name): $_" -Level WARN
                    }
                }

                # Wenn Update fertig UND Logs erhalten → Beenden
                if ($UpdateCompletedFlag.Value -eq $true -and $logsReceived) {
                    Write-Log -Message "($FunctionName) ✓ Finale Logs erhalten, beende Überwachung" -Level INFO
                    $stopwatch.Stop()
                    return $true
                }
            }
        }
        catch {
            Write-Log -Message "($FunctionName) Fehler bei Log-Überwachung: $($_.Exception.Message)" -Level WARN
        }

        # Warte 5 Sekunden
        Start-Sleep -Seconds 5
    }

    # Timeout erreicht
    $stopwatch.Stop()

    if ($logsReceived) {
        Write-Log -Message "($FunctionName) ⏱ Timeout erreicht, aber Logs wurden empfangen" -Level INFO
        return $true
    }
    else {
        Write-Log -Message "($FunctionName) ⏱ Timeout nach $MaxWaitMinutes Minuten ohne Logs" -Level WARN
        return $false
    }
}
#endregion

#region Remove-OldMonitorLogs
function Remove-OldMonitorLogs {
    <#
    .SYNOPSIS
        Löscht alte .lxmon Dateien basierend auf Retention-Policy

    .PARAMETER MonitorLogsPath
        Wurzelverzeichnis der Monitor-Logs

    .PARAMETER RetentionDays
        Anzahl Tage die Logs behalten werden sollen
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MonitorLogsPath,

        [Parameter()]
        [int]$RetentionDays = 30
    )

    $FunctionName = "Remove-OldMonitorLogs"

    if (-not (Test-Path $MonitorLogsPath)) {
        Write-Log -Message "($FunctionName) Monitor-Logs Pfad existiert nicht: $MonitorLogsPath" -Level DEBUG
        return
    }

    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    Write-Log -Message "($FunctionName) Lösche .lxmon Dateien älter als: $($cutoffDate.ToString('yyyy-MM-dd'))" -Level DEBUG

    try {
        $oldLogs = Get-ChildItem -Path $MonitorLogsPath -Recurse -Filter "*.lxmon" -ErrorAction Stop |
                   Where-Object { $_.LastWriteTime -lt $cutoffDate }

        if ($oldLogs) {
            $deletedCount = 0
            foreach ($log in $oldLogs) {
                try {
                    Remove-Item -Path $log.FullName -Force -ErrorAction Stop
                    Write-Log -Message "($FunctionName) Gelöscht: $($log.Name)" -Level DEBUG
                    $deletedCount++
                }
                catch {
                    Write-Log -Message "($FunctionName) Fehler beim Löschen von $($log.Name): $_" -Level WARN
                }
            }

            Write-Log -Message "($FunctionName) $deletedCount alte .lxmon Datei(en) gelöscht" -Level INFO
        }
        else {
            Write-Log -Message "($FunctionName) Keine alten .lxmon Dateien zum Löschen gefunden" -Level DEBUG
        }
    }
    catch {
        Write-Log -Message "($FunctionName) Fehler bei Cleanup: $($_.Exception.Message)" -Level ERROR
    }
}
#endregion

# Export Functions
Export-ModuleMember -Function @(
    'Find-LoxoneMonitorExe',
    'Start-LoxoneMonitorProcess',
    'Stop-LoxoneMonitorProcess',
    'Enable-MiniserverLogging',
    'Disable-MiniserverLogging',
    'Get-LocalIPAddress',
    'Find-LxmonFiles',
    'Watch-MonitorLogs',
    'Remove-OldMonitorLogs'
)

