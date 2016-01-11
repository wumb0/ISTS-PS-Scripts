# Deploys ISTS domain controller

 param ( #add script params here
    [Parameter(Mandatory=$true)][String]$VCenterServerAddress,
    [Parameter(Mandatory=$true)][int]$TeamNumber,
    [String]$VCenterUser,
    [String]$VCenterPassword,
    [String]$GuestUser = "Administrator",
    [String]$GuestPassword = "Student1",
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
}

process { #define main function in here
    #$VMS = Get-VM | Where {$_.Name -contains "ADDNS" -and $_.Folder.Name -eq "Team $TeamNumber"}
    # Uncomment previous line and remove next line for final version, change as needed
    $VMS = Get-VM | Where {$_.Name -eq "ADDNS-$TeamNumber" -and $_.Folder.Name -eq "ISTS-Test"}
    foreach ($VM in $VMS){
        Copy-VMGuestFile -Source .\Deploy-ISTSDomainController.ps1 -Destination C:\Windows\Temp -VM $VM -GuestUser $GuestUser -GuestPassword $GuestPassword -LocalToGuest -Confirm:$false -Force
        Invoke-VMScript -ScriptText "\Windows\Temp\Deploy-ISTSDomainController.ps1 -TeamNumber $TeamNumber -InstallRoles; Remove-Item -Path \Windows\Temp\Deploy-ISTSDomainController.ps1" -VM $VM -RunAsync:$RunAsync -Confirm:$false -GuestUser $GuestUser -GuestPassword $GuestPassword 
    }
}