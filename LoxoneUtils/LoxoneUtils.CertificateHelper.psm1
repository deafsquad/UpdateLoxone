# Certificate validation helper for HTTPS connections
# Provides thread-safe certificate validation bypass for self-signed certificates

function Set-CertificateValidationBypass {
    <#
    .SYNOPSIS
    Sets up certificate validation bypass for self-signed certificates
    
    .DESCRIPTION
    Creates a proper delegate for certificate validation that works in threaded contexts
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Set TLS 1.2 as primary (required for Gen2 miniservers)
        # Only use TLS 1.2 to avoid negotiation issues
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        
        # Check if CertificateValidator type already exists
        $existingType = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
            ForEach-Object { $_.GetTypes() } | 
            Where-Object { $_.Name -eq 'CertificateValidator' } | 
            Select-Object -First 1
        
        if (-not $existingType) {
            # Create a compiled C# class with a static method
            # This works in threaded contexts where script blocks fail
            Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class CertificateValidator {
    public static bool AcceptAll(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
        return true;
    }
}
"@
        }
        
        # Create a proper delegate from the static method
        $methodInfo = [CertificateValidator].GetMethod("AcceptAll")
        $certCallback = [System.Delegate]::CreateDelegate(
            [System.Net.Security.RemoteCertificateValidationCallback],
            $methodInfo
        )
        
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $certCallback
        
        # Additional settings for better HTTPS compatibility
        [System.Net.ServicePointManager]::Expect100Continue = $false
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 10
        
        Write-Log -Level DEBUG -Message "Certificate validation bypass set with TLS 1.2"
        return $true
    } catch {
        Write-Log -Level WARN -Message "Failed to set certificate validation bypass: $_"
        return $false
    }
}

function Clear-CertificateValidationBypass {
    <#
    .SYNOPSIS
    Clears the certificate validation bypass
    
    .DESCRIPTION
    Removes the certificate validation bypass to restore normal certificate checking
    #>
    [CmdletBinding()]
    param()
    
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        Write-Log -Level DEBUG -Message "Certificate validation bypass cleared"
        return $true
    } catch {
        Write-Log -Level WARN -Message "Failed to clear certificate validation bypass: $_"
        return $false
    }
}

# Export functions
Export-ModuleMember -Function Set-CertificateValidationBypass, Clear-CertificateValidationBypass