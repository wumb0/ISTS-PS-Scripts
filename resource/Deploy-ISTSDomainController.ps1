param (
    [Parameter(Mandatory=$true)][int]$TeamNumber,
    [switch]$InstallRoles = $false,
    [switch]$Uninstall = $false,
    [switch]$DNSForward = $false,
    [switch]$All = $false
)

if ($All){
    $InstallRoles = $true
    $DNSForward = $true
}

$SMPass = ConvertTo-SecureString "Password1!" -AsPlainText -Force
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

if ($InstallRoles){
    Write-Host "Installing DNS and ADDS Roles"
    Install-WindowsFeature -Name DNS
    Install-WindowsFeature -Name AD-Domain-Services
    Install-WindowsFeature -Name RSAT-ADDS
    Install-WindowsFeature -Name RSAT-DNS-Server
    Import-Module ADDSDeployment
    Install-ADDSForest -SkipPreChecks -DomainName "team$TeamNumber.ists" -SafeModeAdministratorPassword $SMPass -DomainMode Win2008R2 -ForestMode Win2008R2 -DomainNetbiosName "TEAM$TeamNumber" -Force
}

if ($DNSForward){
    Write-Host "Setting DNS server to forward queries to to 10.2.$TeamNumber.60"
    Get-DnsServerForwarder -ErrorAction SilentlyContinue | Remove-DnsServerForwarder -Force -ErrorAction SilentlyContinue
    Set-DnsServerForwarder -IPAddress 10.2.$TeamNumber.60
}
