param (
    [int]$TeamN    
)


get-vm | where {$_.Name -eq "Team$TeamN-Helpdesk" -or $_.Name -eq "Team$TeamN-win10" -or $_.Name -eq "Team$TeamN-Team0-kali1"} | % {
    Move-VM -Datastore "team$TeamN" -VM $_ -Destination 10.2.$TeamN.10 -DiskStorageFormat Thin
}