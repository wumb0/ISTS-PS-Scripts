
if ( (Get-PSSnapin -Name VMware.VimAutomation.Core -Registered -ErrorAction SilentlyContinue) -ne $null ){
    try {Add-PSSnapin vmware.vimautomation.core -ErrorAction SilentlyContinue} catch {}
} else {
    Write-Error "PowerCLI is not installed. Install PowerCLI and try again"
    exit
}


#### Global Variables ####


#### External Includes ####

#### Misc. Functions ####
function Connect-ISTSVCenter {
    try { #make sure we aren't already connected
        $server = (Get-VIAccount)[0].Server.Name
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

function Import-ISTSConfig {
    param (
        [string]$ConfigFile
    )
    foreach ($line in Get-Content $ConfigFile){
        if ($line[0] -ne "#"){
            $splitline = $line.split("=")
            $varName = $splitline[0].Trim()
            $varValue = $splitline[1..($splitline.length - 1)].TrimStart() -join "="
            Set-Variable -Name ISTS_$varName -Value $varValue -Scope Global
        }
    }
}

#### Read in config ####
Import-ISTSConfig .\ISTS-Scripts.conf
Connect-ISTSVCenter