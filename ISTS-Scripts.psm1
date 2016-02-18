if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null ){
    Write-Error "Make sure vmware.vimautomation.core is added. Import in PowerCLI shell or just Add-PSSnapin"
}

#### Global Variables ####
$ISTS_ModulePath = Split-Path -parent $PSCommandPath

#### Functions ####
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

function Get-VCenterConnectionStatus {
    try {
        $server = (Get-VIAccount -ErrorAction SilentlyContinue)[0].Server.Name
        return $true
    } catch { 
        Write-Error "The vCenter Server is NOT connected, run Connect-ISTSVCenter to connect"
        return $false
    }
}

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

# Deploys ISTS domain controller
function Invoke-DeployISTSDomainController {
    param ( 
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [String]$GuestUser = "Administrator",
        [String]$GuestPassword = "Student1",
        [switch]$RunAsync = $false
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    process {
        foreach ($V in $VM){
            Copy-VMGuestFile -Source $ISTS_ModulePath\resource\Deploy-ISTSDomainController.ps1 -Destination C:\Windows\Temp -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword -LocalToGuest -Confirm:$false -Force
            $DomainName = "$ISTS_BottomLevelDomainNamePrefix$TeamNumber.$ISTS_DomainNameSuffix"
            $NetBiosName = "$ISTS_NetBiosName$TeamNumber".ToUpper()
            Invoke-VMScript -ScriptText "\Windows\Temp\Deploy-ISTSDomainController.ps1 -DomainName $DomainName -NetBiosName $NetBiosName -InstallRoles; Remove-Item -Path \Windows\Temp\Deploy-ISTSDomainController.ps1" -VM $V -RunAsync:$RunAsync -Confirm:$false -GuestUser $GuestUser -GuestPassword $GuestPassword
        }
    }
}

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
        New-Item -ItemType Directory -Force -Path $ISTS_ModulePath\data\$Filename
        Invoke-WebRequest $URL -OutFile $ISTS_ModulePath\data\$Filename
    }
    Copy-VMGuestFile -Source $ISTS_ModulePath\data\$Filename -Destination /tmp -LocalToGuest -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword
    Invoke-VMScript -ScriptText "chmod +x /tmp/$Filename;/tmp/$Filename -- --dont-join --no-legacy install;rm /tmp/$Filename" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $VM
    return $true
}

function Invoke-JoinLinuxHostsToDomain {
    param (
        [Parameter(Mandatory=$true)][int]$TeamNumber,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM,
        [String]$GuestUser = "root",
        [String]$GuestPassword = "student",
        [String]$DomainAdminUser = "Administrator",
        [String]$DomainAdminPassword = "Student1!",
        [String]$DNSServerIP = "172.20.15.38", #change this later, maybe make global
        [switch]$RunAsync = $false
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    process {
        foreach ($V in $VM){
            $OSString = (Invoke-VMScript -ScriptText "uname -a;cat /etc/issue" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $V).ScriptOutput
            if (Install-PBIS -OSString $OSString -VM $V){
                $domain = "$ISTS_BottomLevelDomainNamePrefix$TeamNumber.$ISTS_DomainNameSuffix".ToUpper()
                Invoke-VMScript -ScriptText "echo nameserver $DNSServerIP > /etc/resolv.conf; /opt/pbis/bin/domainjoin-cli join $domain $DomainAdminUser $DomainAdminPassword" -VM $V -GuestUser $GuestUser -GuestPassword $GuestPassword
            }
        }
    }
}

function Start-ISTSDeployFromCSV {
    param (
        [Parameter(Mandatory=$true)][string]$filename,
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [switch]$StartOnCompletion = $false,
        [switch]$TakeBaseSnapshot = [bool]$ISTS_TakeBaseSnapshot
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    $taskTab = @{}
    $nameNetwork = @{}
    Import-Csv $filename | % {
        $Template = $null
        $Template = Get-Template -Name $_.TemplateName -ErrorAction SilentlyContinue

        if ($Template -eq $null){
            $Template = Get-VM -Name $_.TemplateName -ErrorAction SilentlyContinue
        }

        if ($Template -is [System.Array]){
            $Template = $Template[0]
        }

        foreach ($TeamNumber in $TeamNumbers) {
            Write-Progress -Activity "Deploying VMs (0/$($taskTab.Count))" -PercentComplete 0
            $VMFolder = Get-Folder -Name ($ISTS_TeamFolderTemplate.Replace("`$TeamNumber", $TeamNumber))
            $ResourcePool = Get-ResourcePool -Name ($ISTS_TeamResourcePoolTemplate.Replace("`$TeamNumber", $TeamNumber))
            $NetworkName = $ISTS_TeamNetworkTemplate.Replace("`$NetworkID", $_.NetworkID).Replace("`$TeamNumber", $TeamNumber)
            $VMName = $_.TemplateName + "-$TeamNumber"
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
                Get-NetworkAdapter -VM $VM | Set-NetworkAdapter -NetworkName $nameNetwork[$taskTab[$_.Id]] -Confirm:$false | Out-Null
                if ($TakeBaseSnapshot){
                    Write-Progress $activity -PercentComplete $percent -Status $status -CurrentOperation "Taking base snapshot"
                    New-Snapshot -Name "base" -Confirm:$false -VM $VM | Out-Null
                }
                if ($StartOnCompletion){
                    Write-Progress $activity -PercentComplete $percent -Status $status -CurrentOperation "Starting VM"
                    Start-VM -VM $VM | Out-Null
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
        Start-Sleep -Seconds 2
    }
}

function Add-ISTSVMFolders {
    param (
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [Parameter(ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.FolderImpl]$ParentFolder
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    if (!$ParentFolder){
        $message = "No parent folder specified. Create folders in the root of the first datacenter ($((Get-Datacenter)[0]))?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continues"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Exits"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice("Continue?", $message, $options, 0) 
        switch ($result) {
            0 { Write-Host "Continuing" }
            1 { Write-Host -ForegroundColor Red "Aborting."; return }
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

function Add-ISTSResourcePools {
    param (
        [Parameter(Mandatory=$true)][int[]]$TeamNumbers,
        [Parameter(ValueFromPipeline=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.ResourcePoolImpl]$ParentPool
    )
    if (!(Get-VCenterConnectionStatus)) { return }
    if (!$ParentPool){
        $message = "No parent resource pool specified. Create resource pools in the root of the first cluster ($((Get-Cluster)[0]))?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continues"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Exits"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice("Continue?", $message, $options, 0) 
        switch ($result) {
            0 { Write-Host "Continuing" }
            1 { Write-Host -ForegroundColor Red "Aborting."; return }
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



#### Initial config and startup ####
Import-ISTSConfig $ISTS_ModulePath\ISTS-Scripts.conf