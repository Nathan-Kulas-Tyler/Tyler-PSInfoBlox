Function Get-InfoBloxHostipv4addr {
    <#
        .SYNOPSIS
        Retrieves host_ipv4addr records from the InfoBlox server.

		.PARAMETER Reference
        Specifies the direct reference Uri to the resource
              
		.PARAMETER network_view
        Specifies the InfoBlox REST network_view name to return results from 

		.PARAMETER Mac
        Tries to find an host_ipv4record based on this mac address

		.PARAMETER ipv4addr
        Tries to find an host_ipv4record based on this IP address

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

		.RELATED
		https://ipam.illinois.edu/wapidoc/objects/record.host_ipv4addr.html
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param( 
		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Reference,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $network_view,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $cac,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $ipv4addr,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[ValidateSet("bootfile","bootserver","configure_for_dhcp","deny_bootp",
			"discover_now_status","discovered_data","enable_pxe_lease_time","host",
			"ignore_client_requested_options","ipv4addr","is_invalid_mac","last_queried",
			"logic_filter_rules","mac","match_client","ms_ad_user_data","network",
			"network_view","nextserver","options","pxe_lease_time","reserved_interface",
			"use_bootfile","use_bootserver","use_deny_bootp","use_for_ea_inheritance",
			"use_ignore_client_requested_options","use_logic_filter_rules","use_nextserver",
			"use_options","use_pxe_lease_time")]
        [string[]]
        $ReturnAttr,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [int]
        $PageSize = 1000,
		
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
		# https://IBServer/wapi/v2.3/view?_return_fields%2B=disable,forward_only,match_clients
		# bootfile,bootserver,configure_for_dhcp,deny_bootp,discover_now_status,discovered_data,
		# enable_pxe_lease_time,host,ignore_client_requested_options,ipv4addr,is_invalid_mac,last_queried,
		# logic_filter_rules,mac,match_client,ms_ad_user_data,network,network_view,nextserver,options,
		# pxe_lease_time,reserved_interface,use_bootfile,use_bootserver,use_deny_bootp,use_for_ea_inheritance,
		# use_ignore_client_requested_options,use_logic_filter_rules,use_nextserver,use_options,use_pxe_lease_time

		$SearchFields = @{
			network_view = "="
			mac = "~="
			ipv4addr = "~="
		}

		$NextPageID = "NotStarted"
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"

		if ($PSBoundParameters.ContainsKey("Reference")) {
			 $ReqUri = "{0}/{1}" -f $Uri, $Reference
		}
        else { 
			# Add any search fields
			$BaseUri = "{0}/record:host_ipv4addr" -f $Uri
			$ReqUri = "{0}?_paging=1&_max_results=$PageSize&_return_as_object=1" -f $BaseUri
			foreach ($item in $SearchFields.Keys) {
				Write-Verbose "Checking parameters for $item"
				if ( $PSBoundParameters.ContainsKey($item) ) {
					if ( $ReqUri -match "\?" ) {
						$ReqUri = "{0}&{1}{2}{3}" -f $ReqUri, $item, $SearchFields.$item, $PSBoundParameters.$item
					}
					else {
						$ReqUri = "{0}?{1}{2}{3}" -f $ReqUri, $item, $SearchFields.$item, $PSBoundParameters.$item
					}
				}
			}
		}

		if ( $PSBoundParameters.ContainsKey("ReturnAttr") ) {
			$ReturnAttrStr = [string]::Join(",",$ReturnAttr)
			if ( $ReqUri -match "\?" ) {
				$ReqUri = "{0}{1}" -f $ReqUri, "&_return_fields=$ReturnAttrStr"
			}
			else {
				$ReqUri = "{0}{1}" -f $ReqUri, "?_return_fields=$ReturnAttrStr"
			}
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

		do {
			if($NextPageID -notlike "NotStarted") {
				$IRMParams.Uri = $BaseUri, "_page_id=$NextPageID" -join "?"
			}

			try {
				$TempResult = Invoke-RestMethod @IRMParams
			}
			catch {
				Throw "Error retrieving record: $_"
			}
			$NextPageID = $TempResult.next_page_id
            
			Write-Verbose "Page $NextPageID"
			if ( $PassThru ) {
				$TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
			}
			else 
			{
				$TempResult.result
			}

		}
		until (-not $TempResult.next_page_id)
    }
    
    END {}
}