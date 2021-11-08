Function New-InfoBloxDHCPRange {
    <#
        .SYNOPSIS
        Creates a new DHCP Range in Infoblox.
        
        .DESCRIPTION
        Creates a new DHCP Range in Infoblox.
        
        .PARAMETER start_addr
        Specifies the IP Address of the start of the range
		
		.PARAMETER end_addr
        Specifies the IP Address of the end of the range
        
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
        
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/blob/master/cmdlets/Get-IBResourceRecord.ps1
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/tree/master/cmdlets
        https://github.com/RamblingCookieMonster/Infoblox/blob/master/Infoblox/Get-IBRecord.ps1
        https://github.com/Infoblox-API/PowerShell/tree/master/examples

		https://community.infoblox.com/t5/API-Integration/The-definitive-list-of-REST-examples/td-p/1214
		https://ipam.illinois.edu/wapidoc/additional/sample.html
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(
        [Parameter(Mandatory=$True,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [ValidatePattern("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")]
        [string]
        $start_addr,
		
		[Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [ValidatePattern("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")]
        [string]
        $end_addr,
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Uri = $Script:IBConfig.Uri,
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $IBSession = $Script:IBConfig.IBSession,
        
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBServer,

		[switch]
		$DHCP,
        
        [switch]
        $PassThru
    )
    
    BEGIN {
        # If Credential was specified, we can use that to initiate the InfoBlox session. 
        # build a params hashtable to splat to the New-InfoBloxSession function
		if (-not($PSBoundParameters.ContainsKey("Uri")) ) {
			if ( [string]::IsNullOrEmpty($Uri) -and $PSCmdlet.ParameterSetName -eq "Credential" ) {
				if ([string]::IsNullOrEmpty($IBServer) -or [string]::IsNullOrEmpty($IBVersion) ) {
					throw "Unable to determine Uri for IBServer. Specify Uri, or IBVersion and IBServer."
				} #if
				$Uri = "https://{0}/wapi/v{1}" -f $IBServer, $IBVersion
			} #if
		} #if
		Set-TrustAllCertsPolicy

		$ExcludeExpanded = New-Object System.Collections.ArrayList
    } #BEGIN
    
    PROCESS {
        # build Url based on the record type
        $ReqUri = "{0}/range?_return_fields%2b=extattrs" -f $Uri   # %2b in place of +

        <#
			POST /wapi/v1.2/range
			Content-Type: application/json
			{
				"start_addr": "45.0.46.20",
				"end_addr": "45.0.46.101",
			}

			{
				"start_addr": "45.0.46.20",
				"end_addr": "45.0.46.101",
				"server_association_type": "MEMBER" ,
				"member": 
				{
					"_struct": "dhcpmember",
					"ipv4addr" : "192.168.1.3"
				}
     
			}
		#>
        # We need to build the JSON Body
		$BodyHash = @{
			start_addr = $start_addr
		}

		if ( -not ($PSBoundParameters.ContainsKey("end_addr")) ) {
			$end_addr = $start_addr
		}

		$BodyHash.Add("end_addr",$end_addr) | Out-Null

		if ( $DHCP ) {
			$BodyHash.Add("server_association_type","MEMBER") | Out-Null
			$MemberHash = @{
				_struct = "dhcpmember"
				ipv4addr = $IBServer
			}
			$BodyHash.Add("member",$MemberHash) | Out-Null
		}

        $JSON = $BodyHash | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ParameterSetName -eq "Credential" ) {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Post'
				Credential = $Credential
				Body = $JSON
				ContentType = "application/json"
			} #IRMParams Hash
		} #if
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Post'
				WebSession = $IBSession
				Body = $JSON
				ContentType = "application/json"
			} #IRMParams Hash
		} #else

		$UsingParameterSet = "Using {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $UsingParameterSet
        Write-Verbose $ReqUri
		Write-Verbose $JSON
        
        try {
            $TempResult = Invoke-RestMethod @IRMParams
        } #try
        catch {
			# Compliments to JBOSS https://community.infoblox.com/t5/API-Integration/How-to-create-static-DHCP-record-with-API/td-p/4746
			$error = $_
			# throw $_
			
			if ($error.Exception.Response) {
				$InfobloxError = $error.Exception.Response.GetResponseStream()
				$reader = New-Object System.IO.StreamReader($InfobloxError)
				$responseBody = $reader.ReadToEnd();
				throw $responseBody
			}
			
        } #catch
        

        
        if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        } #if
        else {
            $TempResult
        } #else
    } # PROCESS
    
    END {}
}