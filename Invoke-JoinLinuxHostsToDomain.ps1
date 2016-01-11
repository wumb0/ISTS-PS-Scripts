# Joins a linux host to the specified team's domain

 param ( #add script params here
    [Parameter(Mandatory=$true)][String]$VCenterServerAddress,
    [Parameter(Mandatory=$true)][int]$TeamNumber,
    [String]$VCenterUser,
    [String]$VCenterPassword,
    [String]$GuestUser = "root",
    [String]$GuestPassword = "student",
    [String]$DomainAdminUser = "Administrator",
    [String]$DomainAdminPassword = "Student1!",
    [String]$DNSServerIP = "172.20.15.38",
    [switch]$RunAsync = $false
)

begin { #define functions in here
    Add-PSSnapin vmware.vimautomation.core -ErrorAction Stop
    if (!$global:DefaultVIServer){ #make sure we aren't already connected
        if ($VCenterUser -and $VCenterPassword){ 
            Connect-VIServer -Server $VCenterServerAddress -Protocol Https -Force -ErrorAction Stop -User $VCenterUser -Password $VCenterPassword
        } else {
            Connect-VIServer -Server $VCenterServerAddress -Protocol Https -Force -ErrorAction Stop
        }
    }

    function Install-PBIS {
        param (
            [Parameter(Mandatory=$true)][String]$OSString,
            [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]$VM
        )
        Write-Host "Trying to match $($VM.Name)"
        if ($OSString -imatch "ubuntu" -or $OSString -imatch "debian"){
            Write-Host "Matched Debian/Ubuntu"
            $URL = "http://download.beyondtrust.com/PBISO/8.3/pbis-open-8.3.0.3287.linux.x86_64.deb.sh"
        } elseif ($OSString -imatch "suse" -or $OSString -imatch "centos" -or $OSString -imatch "fedora" -or $OSString -imatch ".el") {
            Write-Host "Matched RHEL-based distribution"
            $URL = "http://download.beyondtrust.com/PBISO/8.3/pbis-open-8.3.0.3287.linux.x86_64.rpm.sh"
        } else {
            Write-Warning "Host not matched"
            return $false
        }
        
        $Filename = $URL.Split("/")[-1]
        if (!(Test-Path ./$Filename)){
            Invoke-WebRequest $URL -OutFile $Filename
        }
        Copy-VMGuestFile -Source ./$Filename -Destination /tmp -LocalToGuest -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword
        Invoke-VMScript -ScriptText "chmod +x /tmp/$Filename;/tmp/$Filename -- --dont-join --no-legacy install;rm /tmp/$Filename" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $VM
        return $true
    }
}

process { #define main function in here
    $VMS = Get-VM | Where {$_.ExtensionData.Config.GuestFullName -imatch "linux" -and $_.Folder.Name -eq "ISTS-Test" -and $_.Name -match "domainjoined"}
    foreach ($VM in $VMS){
        $OSString = (Invoke-VMScript -ScriptText "uname -a;cat /etc/issue" -GuestUser $GuestUser -GuestPassword $GuestPassword -VM $VM).ScriptOutput
        if (Install-PBIS -OSString $OSString -VM $VM){
            Invoke-VMScript -ScriptText "echo nameserver $DNSServerIP > /etc/resolv.conf; /opt/pbis/bin/domainjoin-cli join TEAM$TeamNumber.ISTS $DomainAdminUser $DomainAdminPassword" -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword
        }
    }
}