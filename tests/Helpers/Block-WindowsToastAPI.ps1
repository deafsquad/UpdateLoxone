# Block-WindowsToastAPI.ps1
# Blocks Windows Toast notifications at the COM object level
# This is the nuclear option - blocks ALL Windows notifications

# Prevent any Windows.UI.Notifications from working
if (-not $Global:WindowsToastAPIBlocked) {
    $Global:WindowsToastAPIBlocked = $true
    
    # Override New-Object to block toast-related COM objects
    $Global:OriginalNewObject = Get-Command New-Object -CommandType Cmdlet
    function Global:New-Object {
        param(
            [Parameter(Position=0, Mandatory=$true)]
            [string]$TypeName,
            [Parameter(Position=1)]
            [object[]]$ArgumentList,
            [Parameter()]
            [switch]$ComObject,
            [Parameter()]
            [string]$Strict,
            [Parameter()]
            [hashtable]$Property
        )
        
        # Block Windows toast COM objects
        if ($ComObject -and $TypeName -match 'Windows\.UI\.Notifications|Windows\.Data\.Xml\.Dom|ToastNotification') {
            Write-Debug "BLOCKED: COM object creation for $TypeName"
            # Return a mock object that does nothing
            return [PSCustomObject]@{
                TypeName = "Blocked_$TypeName"
                Show = { Write-Debug "BLOCKED: Toast Show() method" }
                LoadXml = { Write-Debug "BLOCKED: LoadXml() method" }
                CreateToastNotifier = { 
                    return [PSCustomObject]@{
                        Show = { Write-Debug "BLOCKED: ToastNotifier.Show()" }
                        Hide = { Write-Debug "BLOCKED: ToastNotifier.Hide()" }
                        Update = { Write-Debug "BLOCKED: ToastNotifier.Update()" }
                    }
                }
                GetTemplateContent = { 
                    Write-Debug "BLOCKED: GetTemplateContent()"
                    return [PSCustomObject]@{
                        GetXml = { "<toast><visual><binding><text>BLOCKED</text></binding></visual></toast>" }
                    }
                }
            }
        }
        
        # Call original for non-toast objects
        $params = @{TypeName = $TypeName}
        if ($PSBoundParameters.ContainsKey('ArgumentList')) { $params['ArgumentList'] = $ArgumentList }
        if ($PSBoundParameters.ContainsKey('ComObject')) { $params['ComObject'] = $ComObject }
        if ($PSBoundParameters.ContainsKey('Property')) { $params['Property'] = $Property }
        
        & $Global:OriginalNewObject @params
    }
    
    # Block Windows Runtime activation
    if (-not $Global:OriginalAddType) {
        $Global:OriginalAddType = Get-Command Add-Type -CommandType Cmdlet -ErrorAction SilentlyContinue
        if ($Global:OriginalAddType) {
            function Global:Add-Type {
                param(
                    [Parameter(Position=0)]
                    [string]$TypeDefinition,
                    [Parameter()]
                    [string]$Name,
                    [Parameter()]
                    [string[]]$MemberDefinition,
                    [Parameter()]
                    [string]$Namespace,
                    [Parameter()]
                    [string[]]$UsingNamespace,
                    [Parameter()]
                    [string]$Path,
                    [Parameter()]
                    [string[]]$LiteralPath,
                    [Parameter()]
                    [string[]]$AssemblyName,
                    [Parameter()]
                    [string[]]$ReferencedAssemblies,
                    [Parameter()]
                    [string]$OutputAssembly,
                    [Parameter()]
                    [string]$OutputType,
                    [Parameter()]
                    [switch]$PassThru,
                    [Parameter()]
                    [switch]$IgnoreWarnings,
                    [Parameter()]
                    [string]$Language,
                    [Parameter()]
                    [string]$CompilerOptions
                )
                
                # Block Windows.UI.Notifications types
                if ($TypeDefinition -match 'Windows\.UI\.Notifications|ToastNotification' -or 
                    $AssemblyName -match 'Windows\.UI|Windows\.Data') {
                    Write-Debug "BLOCKED: Add-Type for Windows notifications"
                    return
                }
                
                # Call original Add-Type
                & $Global:OriginalAddType @PSBoundParameters
            }
        }
    }
    
    # Create fake Windows Runtime types to prevent errors
    if (-not ([System.Management.Automation.PSTypeName]'Windows.UI.Notifications.ToastNotificationManager').Type) {
        Add-Type -TypeDefinition @"
namespace Windows.UI.Notifications {
    public class ToastNotificationManager {
        public static object CreateToastNotifier(string appId) {
            return new FakeToastNotifier();
        }
        public static object GetTemplateContent(int type) {
            return new FakeXmlDocument();
        }
    }
    public class FakeToastNotifier {
        public void Show(object toast) { }
        public void Hide(object toast) { }
        public void Update(object data, object tag, object group) { }
    }
    public class FakeXmlDocument {
        public string GetXml() { return "<toast></toast>"; }
        public void LoadXml(string xml) { }
    }
    public class ToastNotification {
        public ToastNotification(object xml) { }
        public string Tag { get; set; }
        public string Group { get; set; }
        public object Data { get; set; }
    }
}
namespace Windows.Data.Xml.Dom {
    public class XmlDocument {
        public void LoadXml(string xml) { }
        public string GetXml() { return "<toast></toast>"; }
    }
}
"@ -ErrorAction SilentlyContinue
    }
    
    Write-Debug "Windows Toast API completely blocked at COM/Runtime level"
}