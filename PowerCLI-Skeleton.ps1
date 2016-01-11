# PowerCLI script skeleton

 param ( #add script params here
    [Parameter(Mandatory=$true)][String]$VCenterServerAddress,
    [String]$VCenterUser,
    [String]$VCenterPassword
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
    foreach ($Folder in Get-Folder){
        Write-Host "A folder: $($Folder.Name)"
    }
    Write-Host "If folders were displayed above, this probably works"
}