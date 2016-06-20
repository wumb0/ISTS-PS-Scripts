# ISTS-PS-Scripts
Useful scripts to configure VMs with PowerCLI and to deploy AD domains. Written for and used to deploy VMs at SPARSA's ISTS14 competiton

There are a lot of things here, check out [ISTS-Scripts.psm1](ISTS-Scripts.psm1)

## Full list of functions with descriptions
|Function Name			   |Description									|
|:--------------------------------:|----------------------------------------------------------------------------|
|Connect-ISTSVCenter        	   |Connects to vcenter from config or prompt					|
|Get-VCenterConnectionStatus	   |Run a simple test to see if the VCenter server is connected			|
|Import-ISTSConfig                 |Sets variables for use in the script (prefixed by ISTS&#95;)		|
|Invoke-DeployISTSDomainController |Uploads an AD deployment script to the VM's passed in and runs it		|
|Invoke-AddDnsRecordsFromCSV	   |Takes DNS records from a CSV file and adds them to a Windows Server		|
|Install-PBIS			   |Installs PBIS on a linux host						|
|Invoke-JoinLinuxHostsToDomain	   |Gathers linux system info and invokes InstallPBIS on hosts			|
|Add-WindowsHostsToDomain	   |Joins windows hosts to an AD domain						|
|Start-ISTSDeployFromCSV	   |Programatically clones, configures, snapshots, and starts VMs in parallel	|
|Add-ISTSVMFolders		   |Mass adds organizational folders based on team numbers			|
|Add-ISTSResourcePools		   |Mass adds resource pools based on team numbers				|
|Add-ISTSNetworks		   |Mass adds networks based on names, team numbers, and VLAN mappings		|
|Invoke-ConfirmPrompt  		   |Creates a prompt for the user						|


Contribute and stuff
