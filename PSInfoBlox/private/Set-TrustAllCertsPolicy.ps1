#
# Set-TrustAllCertsPolicy
#

Function Set-TrustAllCertsPolicy { 
    <#
    .SYNOPSIS
        Set CertificatePolicy to trust all certs. This will remain in effect for this session.
        
    .Functionality
        Web
        
    .NOTES
        Not sure where this originated. A few references:
            http://connect.microsoft.com/PowerShell/feedback/details/419466/new-webserviceproxy-needs-force-parameter-to-ignore-ssl-errors
            http://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
    #>
    [cmdletbinding()]
    param()
    
    if([System.Net.ServicePointManager]::CertificatePolicy.ToString() -eq "TrustAllCertsPolicy")
    {
        Write-Verbose "Current policy is already set to TrustAllCertsPolicy"
    }
    else
    {
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
    
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
		# Occasionally seeing The request was aborted: Could not create SSL/TLS secure channel.
		# Probably because the API was updated from Tls1 due to POODLE
		# Backlog 7660 / Task 7663
		# https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    }
 }
