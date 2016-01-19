param (
    [switch]$Uninstall = $false,
    [String]$DomainName,
    [String]$NetBiosName,
    [String]$SafeModePassword = "Password1!"
)

if ($Uninstall){
    Write-Host "Uninstalling DNS and ADDS Roles"
    Import-Module ADDSDeployment
    Uninstall-ADDSDomainController -LastDomainControllerInDomain -IgnoreLastDCInDomainMismatch -RemoveDnsDelegation -Confirm:$false -SkipPreChecks -LocalAdministratorPassword $SMPass -ErrorAction SilentlyContinue
    UnInstall-WindowsFeature -Name DNS
    UnInstall-WindowsFeature -Name AD-Domain-Services
    UnInstall-WindowsFeature -Name RSAT-ADDS
    UnInstall-WindowsFeature -Name RSAT-DNS-Server
    exit
}

$SMPass = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
Write-Host "Installing DNS and ADDS Roles"
Install-WindowsFeature -Name DNS
Install-WindowsFeature -Name AD-Domain-Services
Install-WindowsFeature -Name RSAT-ADDS
Install-WindowsFeature -Name RSAT-DNS-Server
Import-Module ADDSDeployment
Install-ADDSForest -SkipPreChecks -DomainName $DomainName -SafeModeAdministratorPassword $SMPass -DomainMode Win2008R2 -ForestMode Win2008R2 -DomainNetbiosName $NetBiosName -Force