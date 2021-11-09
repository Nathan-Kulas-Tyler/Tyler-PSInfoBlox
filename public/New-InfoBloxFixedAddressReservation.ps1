Function New-InfoBloxFixedAddressReservation {
    <#
        .SYNOPSIS
        Creates a new Fixed Address Reservation in Infoblox.
        
        .DESCRIPTION
        Creates a new Fixed Address Reservation in Infoblox.
        
        .PARAMETER IPv4Address
        Specifies the IP Address of the fixed address reservation
		
		.PARAMETER MacAddress
        Specifies the MacAddress of the fixed address reservation
        
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
        $IPAddress,
		
		[Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [ValidatePattern("([0-9A-F]{2}[:-]){5}([0-9A-F]{2})")]
        [string]
        $MacAddress,
        
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
        $PassThru
    )
    
    DynamicParam {
		# https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1 

        # this array holds a list of the parameter names that are added to the parm block. This is they can 
        # be looped through when creating the JSON object for the body
        $DynamicParamList = New-Object System.Collections.ArrayList

        # Dictionary to add to the param block
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        
        # Previously I had each dynamic parameter attribute duplicated in each record type.
        # I think it would be smarter to define these up front, and then simply add them to
        # the attribute collections, and param dictionaries in the individual case blocks.
        
        #region parameter attribute definitions
        $pHostName = New-Object System.Management.Automation.ParameterAttribute
        $pHostName.Mandatory = $true
        $pHostName.HelpMessage = "HostName of the record"
        
        $pCanonical = New-Object System.Management.Automation.ParameterAttribute
        $pCanonical.Mandatory = $true
        $pCanonical.HelpMessage = "Canonical name in FQDN format."
        
        $pipv4Address = New-Object System.Management.Automation.ParameterAttribute
        $pipv4Address.Mandatory = $true
        $pipv4Address.HelpMessage = "IPv4 address of the new A record"
        # http://www.powershelladmin.com/wiki/PowerShell_regex_to_accurately_match_IPv4_address_(0-255_only)
        $ipv4Regex = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'
        $ipv4ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv4Regex)

        $pipv6Address = New-Object System.Management.Automation.ParameterAttribute
        $pipv6Address.Mandatory = $true
        $pipv6Address.HelpMessage = "IPv6 address of the new A record"    
        # IPv6 RegEx - http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        $ipv6Regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
        $ipv6ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv6Regex)

        $pText = New-Object System.Management.Automation.ParameterAttribute
        $pText.Mandatory = $true
        $pText.HelpMessage = "Text associated with the record. It can contain up to 255 bytes per substring, up to a total of 512 bytes."
        
        $pPort = New-Object System.Management.Automation.ParameterAttribute
        $pPort.Mandatory = $true
        $pPort.HelpMessage = "The port of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pPriority = New-Object System.Management.Automation.ParameterAttribute
        $pPriority.Mandatory = $true
        $pPriority.HelpMessage = "The priority of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pTarget = New-Object System.Management.Automation.ParameterAttribute
        $pTarget.Mandatory = $true
        $pTarget.HelpMessage = "The target of the record in FQDN format."
        
        $pWeight = New-Object System.Management.Automation.ParameterAttribute
        $pWeight.Mandatory = $true
        $pWeight.HelpMessage = "The weight of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pPTRDName = New-Object System.Management.Automation.ParameterAttribute
        $pPTRDName.Mandatory = $true
        $pPTRDName.HelpMessage = "The domain name of the DNS PTR record in FQDN format."
        
        $pMailExchanger = New-Object System.Management.Automation.ParameterAttribute
        $pMailExchanger.Mandatory = $true
        $pMailExchanger.HelpMessage = "Mail exchanger name in FQDN format."
        
        $pPreference = New-Object System.Management.Automation.ParameterAttribute
        $pPreference.Mandatory = $true
        $pPreference.HelpMessage = "Preference value, 0 to 65535 (inclusive) in 32-bit unsigned integer format."
        
        $pOrder = New-Object System.Management.Automation.ParameterAttribute
        $pOrder.Mandatory = $true
        $pOrder.HelpMessage = "The order parameter of the NAPTR records. Specifies the order in which NAPTR rules are applied when multiple rules are present (0-65535 inclusive, 32 bit unsigned int)"
        
        $pReplacement = New-Object System.Management.Automation.ParameterAttribute
        $pReplacement.Mandatory = $true
        $pReplacement.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $pComment = New-Object System.Management.Automation.ParameterAttribute
        $pComment.Mandatory = $false
        $pComment.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $pDisable = New-Object System.Management.Automation.ParameterAttribute
        $pDisable.Mandatory = $false
        $pDisable.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."

		$pExclude = New-Object System.Management.Automation.ParameterAttribute
        $pExclude.Mandatory = $false
        $pExclude.HelpMessage = "An array or range of IP addresses to exclude. (Single IP address, or e.g. 192.168.1.1-192.168.1.10)"
        #endregion parameter attribute definitions
		
        return $paramDictionary
    } #DynamicParam
    
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
		$SpecialProcessingParams = @("Network","Range","ConfigureDHCP","MacAddress","Exclude")
		$ExcludeExpanded = New-Object System.Collections.ArrayList
    } #BEGIN
    
    PROCESS {
        # build Url based on the record type
        $ReqUri = "{0}/ﬁxedaddress:{1}?_return_fields%2b=name,zone,extattrs" -f $Uri   # %2b in place of +

		if ( $PSBoundParameters.ContainsKey("Exclude")) {
			ForEach ($item in $PSBoundParameters["Exclude"]) {
				$Expanded = Get-IPsInRange -ipaddress $item
				ForEach ( $expandedItem in $Expanded ) {
					[void]$ExcludeExpanded.Add($expandedItem)
				} #ForEach
			} #ForEach
		} #if

		#IPv4Addr - assign this value to either the passed in value for ipv4addr (else) or, if the UseNextAvailableIp switch was used, set it to the next
		# available IPv4Address in the specified network
		if ( $PSBoundParameters.ContainsKey("UseNextAvailableIp") ) {
			# If UseNextAvailableIp switch was specified, we also need the network or range
			Write-Verbose "Using next available IP"
			if ($PSBoundParameters.ContainsKey("Network")) {
				$IPAddressString = "func:nextavailableip:{0}" -f $PSBoundParameters["Network"]
			} # if 
			elseif ($PSBoundParameters.ContainsKey("Range")) {
				try { 
					[void][ipaddress]::Parse($PSBoundParameters["Range"])
					# This is an IP Address.  Assume it is a start address of the range - lets try to find the range.
					$RangeObj = Get-InfoBloxRange -StartAddress $PSBoundParameters["Range"] -Credential $Credential
					if ( $null -eq $RangeObj ) {
						throw "UseNextAvailableIp switch was specified, valid IP address was passed, but was not a valid range or network."
						return
					} # if 
					if ( $RangeObj.start_addr.Split(".")[3] -eq 0 ) {
						<#
						How to create a network in a specified RANGE, and skip/exclude a specified IP address - in the even the next available IP
						Has a last octet of 0, we do want to skip that address, unless this is a /31.
						{
						"name":  "myrecord.mydomain.com",
						"ipv4addrs":  [
							{
								"ipv4addr":  {
								"_object_function" : "next_available_ip",
								"_object_field" : "ips",
								"_object" : "range",
								"_result_field": "ips", 
								"_parameters" : {
									"num" : 1,
									"exclude" : ["192.168.1.0"]
								},
								"mac":"aa:bb:cc:11:22:21",
								"configure_for_dhcp": true,
								"_object_parameters" : {
									"start_addr" : "192.168.1.0"
								}
								}
							}
						]
						}
						#> 

						$IPAddressString = @{
							"_object_function" = "next_available_ip"
                            "_object_field" = "ips"
                            "_object" = "range"
                            "_result_field" = "ips"
						} #hash ipv4addr
						# Embdedded hashtable _parameters

						[void]$ExcludeExpanded.Add($RangeObj.start_addr)
						$_parameters = @{
							num = 1
							exclude = $ExcludeExpanded
						} #hash

						# Embdedded hashtable _object_parameters
						$_object_parameters = @{
							start_addr = $RangeObj.start_addr
						} #hash

						#Add the embedded hashtables to the parent
						$IPAddressString.Add("_parameters",$_parameters)
						$IPAddressString.Add("_object_parameters",$_object_parameters)
					} #if
					else {
						$IPAddressString = "func:nextavailableip:{0}-{1}" -f $RangeObj.start_addr, $RangeObj.end_addr
					} #else
				} #try
				catch {
					# not an IP Address
					$IPAddressString = "func:nextavailableip:{0}" -f $PSBoundParameters["Range"]
				} #catch
			} # if 
			else {
				throw "UseNextAvailableIp switch was specified, but no network or range was specified."
				return
			} # else
		}
		elseIf ($RecordType -eq "Host" -and $PSBoundParameters.ContainsKey("ipv4addr")) {
			Write-Verbose "Using passed ipv4addr"
			Write-Verbose $PSBoundParameters["ipv4addr"]
			$IPAddressString = $PSBoundParameters["ipv4addr"]
		}
		Write-Verbose "ipv4addr is $IPAddressString"
        
        # We need to build the JSON Body from the Dynamic Parameters
        $ParamHash = @{}
		if ( $PSBoundParameters.ContainsKey("Exclude") -and $PSBoundParameters.ContainsKey("UseNextAvailableIp") -and $RecordType -eq "Host" -and $PSBoundParameters.ContainsKey("Network")) {
			<#
			# JSON for advanced function with excluded IP Addresses.
			{
				"name": "myrecord.mydomain.com", 
				"ipv4addrs": [
				{
				"ipv4addr": {
					"_object_function": "next_available_ip", 
					"_object": "network", 
					"_object_parameters": {
					"network": "192.168.1.0/23"
					}, "_result_field": "ips", 
					"_parameters": {
					"num": 1, 
					"exclude": ["192.169.1.3"]
					}
				}
				}
				]
			}
			#>
			$_parameters = @{
				num = 1
				exclude = [array]$ExcludeExpanded
			} #hash
			$_object_parameters = @{
				network = $PSBoundParameters["Network"]
			} #hash
			$ipv4addrHash = @{
				"_object_function" = "next_available_ip"
				"_object" = "network"
				"_object_parameters" = $_object_parameters
			} #hash
			$ipv4addrHash.Add("_parameters",$_parameters)
			$ipv4addrHash.Add("_result_field","ips")
			
			
			$ipv4addrshash = @{}
			$ipv4addrsHash.Add("ipv4addr",$ipv4addrHash)
			if ( $PSBoundParameters.ContainsKey("MacAddress")) {
				$ipv4addrsHash.Add("mac",$PSBoundParameters["MacAddress"])
				if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
					$ipv4addrsHash.Add("configure_for_dhcp",$true)
				} #if 
			} #if

			$Paramhash.Add("name", $PSBoundParameters["Name"])
			$ParamHash.Add("ipv4addrs",[array]$ipv4addrshash)

		} #if $PSBoundParameters.ContainsKey("Exclude")
		else {
			ForEach ( $DynamicParam in $DynamicParamList ) {
				$Value = $PSBoundParameters[$DynamicParam]
				if ( $PSBoundParameters.ContainsKey($DynamicParam) ) {
					# if Host, ip4addr = ipv4addrs array, etc.
					if ( $arrays -contains $DynamicParam -and $RecordType -eq "Host" ) {
						$Parent = "{0}s" -f $DynamicParam.ToLower()
						$SubHash = @{
							$DynamicParam.ToLower() = $Value
						}
						if ( $DynamicParam -eq "ipv4addr") {
							if ( $PSBoundParameters.ContainsKey("MacAddress")) {
								$SubHash.Add("mac",$PSBoundParameters["MacAddress"])
								if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
									$SubHash.Add("configure_for_dhcp",$true)
								} #if 
							} #if 
						} #if
						$ParamHash.Add($Parent,[array]$SubHash)  # cast subhash as array, so it has the proper format.
					} #if
					elseif ($DynamicParam -eq "UseNextAvailableIp") {
						$Parent = "ipv4addrs"
						$SubHash = @{
							ipv4addr = $IPAddressString
						} #hash

						#if ( $DynamicParam -eq "ipv4addr") {
							if ( $PSBoundParameters.ContainsKey("MacAddress")) {
								$SubHash.Add("mac",$PSBoundParameters["MacAddress"])
								if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
									$SubHash.Add("configure_for_dhcp",$true)
								} #if
							} #if
						#} #if

						$ParamHash.Add($Parent,[array]$SubHash)  # cast subhash as array, so it has the proper format.
					} #elseif
					elseif ($SpecialProcessingParams -contains $DynamicParam ) {
						continue
					} #elseif
					else {
						$ParamHash.Add($DynamicParam.ToLower(),$PSBoundParameters[$DynamicParam])
					} #else
				} #id
			} #ForEach
        } #else
        $JSON = $ParamHash | ConvertTo-Json -Depth 10
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