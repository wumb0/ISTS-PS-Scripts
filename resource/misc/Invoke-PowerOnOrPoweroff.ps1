
    param (
        [Parameter(Mandatory=$true)][int32]$TeamNumber,
        [switch]$PowerOn = $false
    )
    Connect-VIServer -Server 10.0.1.100 -Protocol https -Force -V
    $VMS = Get-VM | where {$_.Name -eq "Team$TeamNumber-" -or $_.Name -eq "Team$TeamNumber-" -or $_.Name -eq "Team$TeamNumber-" -or }

    if ($PowerOn){
        $VMS | Start-VM
    } else {
        $VMS | Stop-VM -confirm:$false
    }