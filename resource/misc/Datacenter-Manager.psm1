$accts = Import-CSV ../BANKACCOUNTS.csv
$white = ($accts | where {$_.team -eq 0})

function Check-TeamPayment {
    param (
        [Parameter(Mandatory=$true)][int32]$TeamNumber
    )
    $acct = ($accts | where {$_.team -eq $TeamNumber})
    $cont = invoke-webrequest -uri http://bankapi.whiteteam.ists:5000/getSession -Method POST -Body @{accountNum=$white.acctnum;password=$white.password} | ConvertFrom-Json
    try {
        $paid = (invoke-webrequest -uri http://bankapi.whiteteam.ists:5000/wasBillPaid -Method POST -Body @{accountNum=$acct.acctnum;session=$cont.SessionID} | ConvertFrom-Json).Paid
        write-host $paid
    } catch {
        $paid = "False"
    }
    if ($paid -eq "True"){
        return $true
    } else {
        return $false
    }
}

function Start-TeamPaymentCheckLoop {
    while ($true) {
        foreach ($i in (1..11)){
            $res = Check-TeamPayment -TeamNumber $i
            if (!$res){
                Write-Host "Team $i is gonna have a bad time"
                Invoke-PowerOnOrPoweroff -TeamNumber $i
            }
        }
        Start-Sleep 300
    }
}