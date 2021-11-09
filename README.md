# Tyler-PSInfoBlox


## Installation: 

    $ProgressPreference = 'SilentlyContinue'
    Add-Type -AssemblyName System.IO.Compression.FileSystem;

    $ModuleName  = 'Tyler-PSInfoBlox'
    $ArchiveName = "{0}.zip" -f $ModuleName
    $Archive = Join-Path $ENV:TEMP $ArchiveName

    $RepositoryZipUrl = "https://api.github.com/repos/Nathan-Kulas-Tyler/$ModuleName/zipball/main" 
    Invoke-RestMethod -Uri $RepositoryZipUrl -Method GET -OutFile $Archive

    $ExtractFolder = Join-Path $ENV:TEMP $ModuleName
    if ( Test-Path $ExtractFolder ) {
    	Remove-Item -Force $ExtractFolder -Recurse
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($Archive, $ExtractFolder);

    $ProfileModulePath = $env:PSModulePath.Split([IO.Path]::PathSeparator)[0]
    if (!(Test-Path $ProfileModulePath)) {
    	New-Item -ItemType Directory -Path $ProfileModulePath
    }

    $pathToInstall = Join-Path $ProfileModulePath $ModuleName
    $path = (Resolve-Path -Path "$ExtractFolder\*").Path
    Move-Item -Path $path -Destination $pathToInstall


## Sample usage

    Import-Module Tyler-PSInfoBlox
    $IBServer = "192.168.1.254"
    $InfoBloxCredential = # Get-secret
    $SubnetDefinition = "192.168.1.0/23"  # Format for subnet definition
    $SubnetSkips = @("192.168.1.0-192.168.1.5","192.168.1.250-192.168.1.255","192.168.2.0-192.168.2.5","192.168.2.250-192.168.2.255") # The first/last 5 addresses in each /24 subnet are reserved in AWS, don't allocate those.
    $Hostrecord = "${computername}.${DomainName}"

    ### Check to see if this record exists
    $IPAssignedAlready = (Get-InfoBloxResourceRecordSet -RecordType Host -SearchField name -eq $Hostrecord -Credential $InfoBloxCredential -IBServer $IBServer -ErrorAction SilentlyContinue).ipv4addrs.ipv4addr


### EXAMPLE 1: this uses the NextAvailable function to obtain an IP address for the new record ###
    if ( [string]::IsNullOrEmpty($IPAssignedAlready) ) {
    Write-Verbose "IP not found in InfoBlox - Creating record for $Hostrecord"
    $MyNewServerIP = (New-InfoBloxResourceRecord -RecordType Host -Network $SubnetDefinition -UseNextAvailable -Name $Hostrecord -Exclude $SubnetSkips -Credential $InfoBloxCredential -IBServer $IBServer).ipv4addrs.ipv4addr
    Write-Verbose "$Hostrecord assigned to IPAddress: $MyNewServerIP"
    } #if 
    else {
        Write-Verbose "IP found in InfoBlox - Using IP $IPAssignedAlready for $Hostrecord"
    }


## EXAMPLE 2:   If you want to add the MAC address to the record, and enable DHCP
    $rest = New-InfoBloxResourceRecord -RecordType Host -UseNextAvailableIp -Network $SubnetDefinition -Name $Hostrecord -Exclude $SubnetSkips -MacAddress $MAC -IBServer $IBServer -Credential $InfoBloxCredential -ConfigureDHCP
    $Object = [pscustomobject]@{
        Hostname   = $rest.ipv4addrs.host
        MAC        = $rest.ipv4addrs.mac
        IP         = $rest.ipv4addrs.ipv4addr
    }
    $Object

## EXAMPLE 3:  If IP Address is already known
    New-InfoBloxResourceRecord -RecordType Host -Network $SubnetDefinition -IPv4Addr $MyIPAddress -Name $Hostrecord -Credential $InfoBloxCredential -IBServer $IBServer
