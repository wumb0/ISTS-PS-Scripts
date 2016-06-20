#Requires -Version 4.0
<#
    ISTS-Scripts.psm1 - powercli scripts to help with ESXi deployment and team replication
    It was designed and used for the deployment of the ISTS14 (2016) competition at RIT
#>

# these checks are for modules
if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null ){
    Write-Error "Make sure vmware.vimautomation.core is added. Import in PowerCLI shell or just Add-PSSnapin VMware.VimAutomation.Core"
}
if ( (Get-Module -Name VMware.VimAutomation.Vds -ErrorAction SilentlyContinue) -eq $null ){
    Write-Warning "Make sure vmware.vimautomation.Vds is added if you want to create networks. Import in PowerCLI shell or just Import-Module VMware.VimAutomation.Vds"
}


# Get the path the module is running in
$ISTS_ModulePath = Split-Path -parent $PSCommandPath

<# Name:        Connect-ISTSVCenter
 # Description: Connects to vcenter from config or prompt
 # Params:      None
 # Returns:     None
 # Throws:      Error if already connected
 # Note:        Creds from the config file are stored as plaintext in memory! Be careful! 
 #>
function Connect-ISTSVCenter {
    try { #make sure we aren't already connected
        $server = (Get-VIAccount -ErrorAction SilentlyContinue)[0].Server.Name
        Write-Warning "It looks like you are already connected to the server at `"$server`", disconnect with Disconnect-VIServer and then try again"
    } catch { 
        if ($ISTS_VCenterUser -and $ISTS_VCenterPassword){
            Write-Warning "These credentials are stored in memory in plain text, just so you know"
            Connect-VIServer -Server $ISTS_VCenterServerAddress -Protocol Https -Force -ErrorAction Stop -User $ISTS_VCenterUser -Password $ISTS_VCenterPassword
        } else {
            Connect-VIServer -Server $ISTS_VCenterServerAddress -Protocol Https -Force -ErrorAction Stop
        }
    }
}

<# Name:        Get-VCenterConnectionStatus
 # Description: Run a simple test to see if the VCenter server is connected
 # Params:      None
 # Returns:     $true if vcenter is connected, $false if not
 # Throws:      Error if check fails
 #>
function Get-VCenterConnectionStatus {
    try {
        $server = (Get-VIAccount -ErrorAction SilentlyContinue)[0].Server.Name
        return $true
    } catch { 
        Write-Error "The vCenter Server is NOT connected, run Connect-ISTSVCenter to connect"
        return $false
    }
}

<# Name:        Import-ISTSConfig
 # Description: Sets variables for use in the script (prefixed by ISTS_)
 # Params:      ConfigFile - The path to the configuration file to load
 # Returns:     None
 # Throws:      None
 #>
function Import-ISTSConfig {
    param (
        [string]$ConfigFile
    )
    foreach ($line in Get-Content $ConfigFile){
        if ($line[0] -ne "#"){
            $splitline = $line.split("=")
            $varName = $splitline[0].Trim()
            $varValue = $splitline[1..($splitline.length - 1)].TrimStart() -join "="
            Set-Variable -Name ISTS_$varName -Value $varValue -Scope Script
        }
    }
}

<# Name:        Invoke-DeployISTSDomainController
 # Description: Uploads an AD deployment script to the VM's passed in and runs it
 # Params:      TeamNumber - int,required - The team number to insert
 #              VM - VirtualMachineImpl,required - the VM to run the script on
 #              GuestUser - string - Username to use to log into the VM
 #                                 - Populated by ISTS_DomainAdminUser if blank
 #              GuestPassword - string - Password to use to log into the VM
 #                                     - Populated by ISTS_DomainAdminPassword if blank
 #              RunAsync - bool - Whether to wait between starting each deployment
 # Returns:     None
 # Throws:      None
 #>
function Invoke-DeployISTSDomainController {
    param ( 
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [String]$GuestUser = $ISTS_DomainAdminUser,
        [String]$GuestPassword = $ISTS_DomainAdminPassword,
        [switch]$RunAsync = $false
    )
    begin {
        if (!(Get-VCenterConnectionStatus)) { return }
    }
    process {
        foreach ($V in $VM){
            Copy-VMGuestFile -Source $ISTS_ModulePath\resource\Deploy-ISTSDomainController.ps1 -Destination C:\Windows\Temp -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -LocalToGuest -Confirm:$false -Force
            $DomainName = $ISTS_DomainNameTemplate.replace("`$TeamNumber", $TeamNumber).ToUpper()
            $NetBiosName = $ISTS_NetBiosNameTemplate.replace("`$TeamNumber", $TeamNumber).ToUpper()
            Invoke-VMScript -ScriptText "\Windows\Temp\Deploy-ISTSDomainController.ps1 -DomainName $DomainName -NetBiosName $NetBiosName -InstallRoles; Remove-Item -Path \Windows\Temp\Deploy-ISTSDomainController.ps1" -VM $V -RunAsync:$RunAsync -Confirm:$false -GuestUser $GuestUser -GuestPassword $GuestPassword
        }
    }
}

<# Name:        Invoke-AddDnsRecordsFromCSV
 # Description: Takes DNS records from a CSV file and adds them to a Windows Server
 # Params:      TeamNumber - int,required - The team number to use in the script
 #              VM - VirtualMachineImpl,required - the VM to run the script on
 #              GuestUser - string - Username to use to log into the VM
 #                                 - Populated by ISTS_DomainAdminUser if blank
 #              GuestPassword - string - Password to use to log into the VM
 #                                     - Populated by ISTS_DomainAdminPassword if blank
 #              RunAsync - bool - Whether to wait between starting each deployment
 # Returns:     None
 # Throws:      None
 # Note:        Powershell required on the VM guest
 #>
# Adds dns records
function Invoke-AddDnsRecordsFromCSV {
    param ( 
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [Parameter(Mandatory=$true)]$FileName,
        [String]$GuestUser = $ISTS_DomainAdminUser,
        [String]$GuestPassword = $ISTS_DomainAdminPassword,
        [switch]$RunAsync = $false
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    Copy-VMGuestFile -Source $ISTS_ModulePath\resource\Add-DnsRecordsFromCSV.ps1 -Destination C:\Windows\Temp -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword -LocalToGuest -Confirm:$false -Force
    Copy-VMGuestFile -Source $FileName -Destination C:\Windows\Temp -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword -LocalToGuest -Confirm:$false -Force
    Invoke-VMScript -ScriptText "\Windows\Temp\Add-DnsRecordsFromCSV.ps1 -TeamNumber $TeamNumber -FileName \Windows\Temp\$FileName; Remove-Item -Path \Windows\Temp\Add-DnsRecordsFromCSV.ps1;Remove-Item -Path \Windows\Temp\$FileName" -VM $VM -RunAsync:$RunAsync -Confirm:$false -GuestUser $GuestUser -GuestPassword $GuestPassword
}

<# Name:        Install-PBIS
 # Description: Installs PBIS on a linux host
 # Params:      OSString - string,required - Info that could help identify the OS
 #              VM - VirtualMachineImpl,required - the VM to install PBIS on
 # Returns:     $true if install succeeded, $false if not
 # Throws:      None
 # Note:        This will download PBIS from the link in the imported ISTS-Config
 #>
function Install-PBIS {
    param (
        [Parameter(Mandatory=$true)][String]$OSString,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    Write-Host "Trying to match $($VM.Name)"
    if ($OSString -imatch "ubuntu" -or $OSString -imatch "debian"){
        Write-Host "Matched Debian/Ubuntu"
        $URL = $ISTS_PbisDebURL
    } elseif ($OSString -imatch "suse" -or $OSString -imatch "centos" -or $OSString -imatch "fedora" -or $OSString -imatch ".el") {
        Write-Host "Matched RHEL-based distribution"
        $URL = $ISTS_PbisRpmURL
    } else {
        Write-Warning "Host not matched"
        return $false
    }

    $Filename = $URL.Split("/")[-1]
    if (!(Test-Path .\data\$Filename)){
        New-Item -ItemType Directory -Force -Path $ISTS_ModulePath\data
        Invoke-WebRequest $URL -OutFile $ISTS_ModulePath\data\$Filename
    }
    Copy-VMGuestFile -Source $ISTS_ModulePath\data\$Filename -Destination /tmp -LocalToGuest -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword -Force
    Invoke-VMScript -ScriptText "chmod +x /tmp/$Filename;/tmp/$Filename -- --dont-join --no-legacy install;rm /tmp/$Filename" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $VM -Confirm:$false
    return $true
}

<# Name:        Invoke-JoinLinuxHostsToDomain
 # Description: Gathers linux system info and invokes Install-PBIS on hosts
 # Params:      TeamNumber - int,required - The team number that is being joined
 #              VM - VirtualMachineImpl,required - The VM's join to the domain
 #              GuestUser - string - Username to use to log into the VM
 #                                 - Populated by ISTS_LinuxDefaultUser if blank
 #              GuestPassword - string - Password to use to log into the VM
 #                                     - Populated by ISTS_LinuxDefaultPassword if blank
 #              DomainAdminUser - string - Domain admin user name to use to join the domain
 #              DomainAdminPassword - string - Domain admin user password to use to join the domain
 #              DNSServerIP - string - The IP address of the DNS server for the team
 #              RunAsync - bool - Whether to run the joins asynchronously
 # Returns:     None
 # Throws:      None
 # Note:        Can process multiple VMs at once via pipe
 # Note:        If you want to set the DNS server statically then just assign the var, it won't be changed
 #>
function Invoke-JoinLinuxHostsToDomain {
    param (
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [String]$GuestUser = $ISTS_LinuxDefaultUser,
        [String]$GuestPassword = $ISTS_LinuxDefaultPassword,
        [String]$DomainAdminUser = $ISTS_DomainAdminUser,
        [String]$DomainAdminPassword = $ISTS_DomainAdminPassword,
        [String]$DNSServerIP = $ISTS_DomainControllerIPTemplate.replace("`$TeamNumber", $TeamNumber),
        [switch]$RunAsync = $false
    )
    begin {
        if (!(Get-VCenterConnectionStatus)) { return }
    }
    process {
        foreach ($V in $VM){
            $OSString = (Invoke-VMScript -ScriptText "uname -a;cat /etc/issue" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $V).ScriptOutput
            if (Install-PBIS -OSString $OSString -VM $V){
                $domain = $ISTS_DomainNameTemplate.replace("`$TeamNumber", $TeamNumber).ToUpper()
                Invoke-VMScript -ScriptText "echo nameserver $DNSServerIP > /etc/resolv.conf; /opt/pbis/bin/domainjoin-cli join $domain $DomainAdminUser $DomainAdminPassword" -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -RunAsync:$RunAsync -Confirm:$false
            }
        }
    }
}

<# Name:        Add-WindowsHostsToDomain
 # Description: Joins windows hosts to an AD domain
 # Params:      TeamNumber - int,required - The team number that is being joined
 #              VM - VirtualMachineImpl,required - The VM's join to the domain
 #              GuestUser - string - Username to use to log into the VM
 #                                 - Populated by ISTS_WindowsDefaultUser if blank
 #              GuestPassword - string - Password to use to log into the VM
 #                                     - Populated by ISTS_WindowsDefaultPassword if blank
 #              DomainAdminUser - string - Domain admin user name to use to join the domain
 #              DomainAdminPassword - string - Domain admin user password to use to join the domain
 #              DNSServerIP - string - The IP address of the DNS server for the team
 #              RunAsync - bool - Whether to run the joins asynchronously
 # Returns:     None
 # Throws:      None
 # Note:        Can process multiple VMs at once via pipe
 # Note:        If you want to set the DNS server statically then just assign the var, it won't be changed
 #>
function Add-WindowsHostsToDomain{
    param (
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [String]$GuestUser = $ISTS_WindowsDefaultUser,
        [String]$GuestPassword = $ISTS_WindowsDefaultPassword,
        [String]$DomainAdminUser = $ISTS_DomainAdminUser,
        [String]$DomainAdminPassword = $ISTS_DomainAdminPassword,
        [String]$DNSServerIP = $ISTS_DomainControllerIPTemplate.replace("`$TeamNumber", $TeamNumber),
        [switch]$RunAsync = $false
    )
    begin {
        if (!(Get-VCenterConnectionStatus)) { return }
        $domain = $ISTS_DomainNameTemplate.replace("`$TeamNumber", $TeamNumber)
    }
    process {
        foreach ($V in $VM){
            Invoke-VMScript -ScriptText "netsh int ipv4 set dns 'Local Area Connection' static 10.2.$TeamNumber.20" -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -Confirm:$false
            Invoke-VMScript -ScriptText "Set-DnsClientServerAddress -ServerAddress $DNSServerIP -InterfaceAlias ((Get-NetAdapter | Where {`$_.Name -Like '*Ethernet*' -or `$_.Name -Like '*Local Area Connection*'})[0])" -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -Confirm:$false
            Invoke-VMScript -ScriptText "Add-Computer -DomainName '$domain' -Credential (New-Object System.Management.Automation.PSCredential('$DomainAdminUser@$domain',('$DomainAdminPassword' | ConvertTo-SecureString -asPlainText -Force)))" -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -RunAsync:$RunAsync -Confirm:$false
        }
    }
}

<# Name:        Start-ISTSDeployFromCSV
 # Description: Programatically clones, configures, snapshots, and starts VMs in parallel
 # Params:      FileName - string,required - The CSV file name to deploy from
 #              TeamNumbers - int[],required - The teams to deploy to
 #              StartOnCompletion - bool - Whether to start the VM when the process is finished
 #              TakeBaseSnapshot - bool - Whether to take a base snapshot of the VM when the process is finished
 # Returns:     None
 # Throws:      None
 # Note:        If you don't want this script to deploy networks then provide a bogus network name
 #>
function Start-ISTSDeployFromCSV {
    param (
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [switch]$StartOnCompletion = [bool]$ISTS_StartOnCompletion,
        [switch]$TakeBaseSnapshot = [bool]$ISTS_TakeBaseSnapshot
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    $taskTab = @{}
    $nameNetwork = @{}
    Import-Csv $FileName | % {
        $Template = $null
        $Template = Get-Template -Name $_.TemplateName -ErrorAction SilentlyContinue

        if ($Template -eq $null){
            $Template = Get-VM -Name $_.TemplateName -ErrorAction SilentlyContinue
        }

        if ($Template -is [System.Array]){
            $Template = $Template[0]
        }

        if ($Template -eq $null){
            Write-Warning "No template named $($_.TemplateName), skipping" 
        } else {

            foreach ($TeamNumber in $TeamNumbers) {
                Write-Progress -Activity "Deploying VMs (0/$($taskTab.Count))" -PercentComplete 0
                $VMFolder = Get-Folder -Name ($ISTS_TeamFolderTemplate.Replace("`$TeamNumber", $TeamNumber))
                $ResourcePool = Get-ResourcePool -Name ($ISTS_TeamResourcePoolTemplate.Replace("`$TeamNumber", $TeamNumber))
                $NetworkName = $ISTS_TeamNetworkTemplate.Replace("`$NetworkID", $_.NetworkID).Replace("`$TeamNumber", $TeamNumber)
                $VMName = $ISTS_TeamVMNameTemplate
                $tmp = $_.TemplateName
                $ISTS_TeamVmNameReplace.Split(",") | % { 
                    if ($tmp.Contains($_)){
                        $tmp = $tmp.TemplateName.Replace($_, "")
                    }
                }
                $VMName = $VMName.Replace("`$TeamNumber", $TeamNumber).Replace("`$TemplateName", $tmp)
                $ID = $null
                try {
                    if (!$NetAdaptersOnly){
                        if ($Template.GetType().fullname -like "*TemplateImpl"){
                            $ID = (New-VM -Template $Template -Name $VMName -Location $VMFolder -ResourcePool $ResourcePool -RunAsync).Id
                            $taskTab[$ID] = $VMName
                        } elseif ($Template.getType().fullname -like "*VirtualMachineImpl") {
                            $ID = (New-VM -VM $Template -Name $VMName -Location $VMFolder -ResourcePool $ResourcePool -RunAsync).Id
                            $taskTab[$ID] = $VMName
                        } else { continue }
                    }
                } catch {
                    if ($ID -ne $null){
                        $taskTab.Remove($ID)
                    }
                    continue
                }
                Write-Host -ForegroundColor Yellow "Deploying $VMName to $($VMFolder.Name)"
                $nameNetwork[$VMName] = $NetworkName
            } 
        }
    }
    # adapted from http://www.lucd.info/2010/02/21/about-async-tasks-the-get-task-cmdlet-and-a-hash-table/
    # Set netadapter on each completed VM
    $runningTasks = $taskTab.Count
    $initialTasks = $runningTasks
    while($runningTasks -gt 0){
        Get-Task | % {
            if($taskTab.ContainsKey($_.Id) -and $_.State -eq "Success"){
                $VM = Get-VM $taskTab[$_.Id]
                $percent = 100*($initialTasks-$runningTasks)/$initialTasks
                $activity = "Deploying VMs ($($initialTasks-$runningTasks)/$initialTasks)"
                $status = "Configuring $($VM.Name)"
                Write-Progress $activity -PercentComplete $percent -Status $status -CurrentOperation "Setting network adapter"
                Get-NetworkAdapter -VM $VM | Set-NetworkAdapter -NetworkName $nameNetwork[$taskTab[$_.Id]] -Confirm:$false -RunAsync:(!$TakeBaseSnapshot) | Out-Null
                if ($TakeBaseSnapshot){
                    Write-Progress $activity -PercentComplete $percent -Status $status -CurrentOperation "Taking base snapshot"
                    New-Snapshot -Name "base" -Confirm:$false -VM $VM | Out-Null
                }
                if ($StartOnCompletion){
                    Write-Progress $activity -PercentComplete $percent -Status $status -CurrentOperation "Starting VM"
                    Start-VM -VM $VM -RunAsync | Out-Null
                }
                Write-Host -ForegroundColor Green "Finished deploying $($VM.Name)"
                $taskTab.Remove($_.Id)
                $runningTasks--
            }
            elseif($taskTab.ContainsKey($_.Id) -and $_.State -eq "Error"){
                Write-Host -ForegroundColor Red "Error deploying $($taskTab[$_.Id])"
                $taskTab.Remove($_.Id)
                $runningTasks--
            }
        }
        Write-Progress "Deploying VMs ($($initialTasks-$runningTasks)/$initialTasks)" -PercentComplete (100*($initialTasks-$runningTasks)/$initialTasks) -Status "Deploying"
        Start-Sleep -Seconds 1
    }
}

<# Name:        Add-ISTSVMFolders
 # Description: Mass adds organizational folders based on team numbers
 # Params:      TeamNumbers - int[],required - List of team folders to add
 #              ParentFolder - FolderImpl,required - Folder to place created folders under
 # Returns:     None
 # Throws:      None
 # Note:        Uses ISTS_TeamFolderTemplate to name the folders
 #>
function Add-ISTSVMFolders {
    param (
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [Parameter(ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.FolderImpl]$ParentFolder
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    if (!$ParentFolder){
        $message = "No parent folder specified. Create folders in the root of the first datacenter ($((Get-Datacenter)[0]))?"
        if (!(Invoke-ConfirmPrompt -Message $message)){
            return
        }
    }
    $TeamNumbers | % {
        $fname = $ISTS_TeamFolderTemplate.Replace("`$TeamNumber", $_)
        $topdcfolder = get-view (get-view -ViewType datacenter -Filter @{"name"=(Get-Datacenter)[0].Name}).VmFolder
        Write-Host "Creating folder $fname"
        if ($ParentFolder){
            New-Folder -Name $fname -Location $ParentFolder | Out-Null
        } else {
            $topdcfolder.CreateFolder($fname) | Out-Null
        }
    }
}

<# Name:        Add-ISTSResourcePools
 # Description: Mass adds resource pools based on team numbers
 # Params:      TeamNumbers - int[],required - List of team resource pools to add
 #              ParentPool - ResourcePoolImpl,required - Pool to place created pools under
 # Returns:     None
 # Throws:      None
 # Note:        Uses ISTS_TeamResourcePoolTemplate to name the resource pools
 #>
function Add-ISTSResourcePools {
    param (
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [Parameter(ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.ResourcePoolImpl]$ParentPool
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    if (!$ParentPool){
        if (!(Invoke-ConfirmPrompt -Message "No parent resource pool specified. Create resource pools in the root of the first cluster ($((Get-Cluster)[0]))?")){
            return
        }
    }
    $TeamNumbers | % {
        $pname = $ISTS_TeamResourcePoolTemplate.Replace("`$TeamNumber", $_)
        Write-Host "Creating pool $pname"
        if ($ParentPool){
            New-ResourcePool -Name $pname -Location $ParentPool | Out-Null
        } else {
            New-ResourcePool -Name $pname -Location (Get-Cluster)[0] | Out-Null
        }
    }
}

<# Name:        Add-ISTSNetworks
 # Description: Mass adds networks based on names, team numbers, and VLAN mappings
 # Params:      TeamNumbers - int[],required - List of teams to add networks for
 #              NetworkNames - string[],required - List of network names to add
 #              ParentDVSwitchName - string - Name of the parent DVSwitch
 #                                          - Gets default from ISTS_ParentDVSwitch
 #              VlanIDMappings - string - VLAN ID mapping string for users/networks
 #                                      - Gets default from ISTS_VlanIDMappings
 # Returns:     None
 # Throws:      None
 # Note:        Check out how VlanIDMappings are set up in the example config
 # Note:        Uses ISTS_TeamNetworkTemplate from the config to name networks
 #>
function Add-ISTSNetworks {
    param (
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [Parameter(Mandatory=$true)][string[]]$NetworkNames,
        [string]$ParentDVSwitchName = $ISTS_ParentDVSwitchName,
        [string]$VlanIDMappings = $ISTS_VlanIDMappings
    )
    $VDSwitch = Get-VDSwitch -Name $ParentDVSwitchName -ErrorAction Stop
    foreach ($Team in $TeamNumbers){
        foreach ($NetID in $NetworkNames){
            $NetName = $ISTS_TeamNetworkTemplate.Replace("`$TeamNumber", $Team).Replace("`$NetworkID", $NetID)
            $VlanID = [int]($VlanIDMappings.split(' ') | Where {$_.Split(":")[0] -eq $Team -and $_.Split(":")[1] -eq $NetID}).split(":")[2]
            New-VDPortGroup -VDSwitch $VDSwitch -Name "$NetName" -VLanId $VlanID
        }
    }

}

<# Name:        Invoke-ConfirmPrompt
 # Description: Creates a prompt for the user
 # Params:      Title - string - The title of the prompt
 #              Message - string - The prompt message/question
 #              YesPrompt - string - What to display next to the yes option
 #              NoPrompt - string - What to display next to the no option
 #              OnYes - string - What to print if the user says yes
 #              OnNo - string - What to print if the user says no
 # Returns:     $true if the user answers with yes, $false if no
 # Throws:      None
 #>
function Invoke-ConfirmPrompt {
    param(
        [string]$Title = "Continue?",
        [string]$Message = "",
        [string]$YesPrompt = "Continue",
        [string]$NoPrompt = "Exit",
        [string]$OnYes = "Continuing",
        [string]$OnNo = "Aborting"
    )
   
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $YesPrompt
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $NoPrompt
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.ui.PromptForChoice($Title, $Message, $options, 0) 
    switch ($result) {
        0 { Write-Host $OnYes; return $true }
        1 { Write-Host -ForegroundColor Red $OnNo; return $false }
    }
}

#### Initial config and startup ####
Import-ISTSConfig $ISTS_ModulePath\ISTS-Scripts.conf
