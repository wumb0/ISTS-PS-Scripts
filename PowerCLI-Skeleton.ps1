# PowerCLI script skeleton

 param ( #add script params here
    [Parameter(Mandatory=$true)][String]$VCenterServerAddress
)

begin { #define functions in here
    Add-PSSnapin vmware.vimautomation.core -ErrorAction Stop
    Connect-VIServer -Server $VCenterServerAddress -Protocol Https -Force -ErrorAction Stop
}

process { #define main function in here
    foreach ($Folder in Get-Folder){
        Write-Host "A folder: $($Folder.Name)"
    }
    Write-Host "If folders were displayed above, this probably works"
}