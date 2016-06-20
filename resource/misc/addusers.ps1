# adds users in the form name|password from CSV users.txt
param (
	[switch]$DryRun = $false,
	[string]$UserFile = "users.txt",
	[Parameter(Mandatory=$true)][Int32]$TeamNumber,
	[switch]$DeleteUsers
)

$csv = Import-CSV $UserFile -Delimiter "|" 

foreach ($l in $csv){
	$name = $l.name.split(" ")
	$fname = $name[0]
	if ($name.length -eq 1){
		$lname = ""
		$email = "$fname".ToLower() + "@team$TeamNumber.ists"
	} else {
		$lnames = $name[1..($name.length-1)] -join " "
		$lname = $lnames.replace(" ", '')
		$email = "$fname.$($lnames.replace(' ', '.')".ToLower() + "@team$TeamNumber.ists"
	}
	if ($fname.length -ge 20){
		$sam = ($fname.substring(0,19)) + $lname[0]
	} else {
		$sam = $fname + $lname[0]
	}
	$pass = $l.password
	Write-Host "$fname $lname $email"
	if ($DeleteUsers){
		Get-Aduser -filter {Name -eq $fname} | Remove-ADUser -Confirm:$false -Whatif:$DryRun
	} else { 
		New-ADUser -DisplayName ((($fname, $lname) -join " ").Trim()) -UserPrincipalName "$email" -SamAccountName $sam -Name "$fname" -Surname "$lname" -AccountPassword (ConvertTo-SecureString -Asplaintext "$pass" -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=team$TeamNumber,DC=ISTS" -WhatIf:$DryRun
	}
}
