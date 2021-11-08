Function Get-InfoBloxZone {
    <#
        .SYNOPSIS
        Retrieves Zone records from the InfoBlox server.
              
		.PARAMETER Zone
        Specifies the InfoBlox REST zone name to return

        .PARAMETER Uri
        Specifies the InfoBlox REST server Base Uri. Not required if you are using sessions, and will default based on the default
        specified in New-InfoBloxSession if not specified.
        
        .PARAMETER IBVersion
        Specifies InfoBlox version. This is used for crafting the BaseUri in the New-InfoBloxSession function if 
        Credentials are specified instead of a session.
        
        .PARAMETER IBSession
        Created with the New-InfoBloxSession function. This commandlet will be run anyway if the credentials only are specified, 
        in the begin block.
        
        .PARAMETER Credential
        Credential object with user Id and password for creating an InfoBlox Grid session.
        
        .PARAMETER IBServer
        Passed to the New-InfoBlox session function if a Credential is specified instead of a session.
        
        .PARAMETER Passthru
        If specified, this switch will cause the IBSession created in this function to be pased to the pipeline in the output object, 
        so it can be utilized, and not recreated in subsequent function calls.
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(    
		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Zone,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $View,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string[]]
        $ReturnAttr,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Reference,

        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Uri =  $Script:IBConfig.Uri,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $IBSession = $Script:IBConfig.IBSession,
        
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBServer,
        
        [switch]
        $PassThru
    )
    
    BEGIN {
        Set-TrustAllCertsPolicy
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"
        $BaseUri = "{0}/zone_auth" -f $Uri
        
		if ( $PSBoundParameters.ContainsKey("Zone") ) {
			$ReqUri = "{0}?fqdn={1}" -f $BaseUri, $Zone
		}
		elseif ($PSBoundParameters.ContainsKey("Reference")) {
			$ReqUri = $Uri, $Reference -join "/"
		}
		else {
			$ReqUri = $BaseUri
		}

		if ( $PSBoundParameters.ContainsKey("View") ) {
			if ( $ReqUri -match "\?" ) {
				$ReqUri = "{0}{1}" -f $ReqUri, "&view=$View"
			}
			else {
				$ReqUri = "{0}{1}" -f $ReqUri, "?view=$View"
			}
		}

		if ( $PSBoundParameters.ContainsKey("ReturnAttr") ) {
			$ReturnAttrStr = [string]::Join(",",$ReturnAttr)
			if ( $ReqUri -match "\?" ) {
				$ReqUri = "{0}{1}" -f $ReqUri, "&_return_fields%2B=$ReturnAttrStr"
			}
			else {
				$ReqUri = "{0}{1}" -f $ReqUri, "?_return_fields%2B=$ReturnAttrStr"
			}
		}
        
		if ( $ReqUri -match "\?" ) {
			$ReqUri = "{0}{1}" -f $ReqUri, '&_max_results=500000'
		}
		else {
			$ReqUri = "{0}{1}" -f $ReqUri, '?_max_results=500000'
		}
		

		if ( $PSCmdlet.ParameterSetName -eq "Session") {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Get'
				WebSession = $IBSession
			}
		}
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Get'
				Credential = $Credential
			}
		}
        
        Write-Verbose $ReqUri

		try {
            $TempResult = Invoke-RestMethod @IRMParams
        }
        catch {
            Throw "Error retrieving record: $_"
        }

		if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        }

        $TempResult
    }
    
    END {}
}