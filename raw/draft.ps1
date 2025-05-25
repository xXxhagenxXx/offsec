function enumObjectswithDCsyncRights{
	param($Server = $Server)
	$Domain = $Server -split '\.'	
$DCSyncLists = @()
$AllReplACLs = (Get-AcL "ad:\dc=$($Domain[0]),dc=$($Domain[1]),dc=$($Domain[2])").Access | Where-Object {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c'} | select-object -Unique IdentityReference
#Filter this list to RIDs above 1000 which will exclude well-known Administrator groups

# Loop to find Groups that have DCSync rights
foreach ($ACL in $AllReplACLs)
{
    $user = New-Object System.Security.Principal.NTAccount($ACL.IdentityReference)
    $SID = $user.Translate([System.Security.Principal.SecurityIdentifier])
    $RID = $SID.ToString().Split("-")[7]
    if([int]$RID -lt 1000)
    {
	$split = $ACL.IdentityReference -split '\\'
        #Write-Host "Permission to Sync AD granted to:" $split[1]
	$GroupMembers = Get-ADGroupMember -Server $Server -Identity $split[1] -Recursive | Select-Object -Unique -ExpandProperty SamAccountName
	#Write-Host "Permission to Sync AD granted to:" $GroupMembers
	foreach ($member in $GroupMembers){
		if ($member -notcontains $DCSyncLists){
			$DCsyncLists += $member
		}
	}
    }
}

# Loop to find users with DCSyncrights
foreach ($ACL in $AllReplACLs)
{
    $user = New-Object System.Security.Principal.NTAccount($ACL.IdentityReference)
    $SID = $user.Translate([System.Security.Principal.SecurityIdentifier])
    $RID = $SID.ToString().Split("-")[7]
    if([int]$RID -gt 1000)
    {
	$split = $ACL.IdentityReference -split '\\'
#       Write-Host "Permission to Sync AD granted to:" $split[1]
	if ($split[1] -notcontains $DCSyncLists){
		$DCSyncLists += $split[1]
	}
    }
}

$DCSyncListsUnique = $DCSyncLists | Select-Object -Unique
}


enumAdminsNotProtected{
	param($FileName = $adminGroups, $Server)
	# Create an array to store filtered members
	$filteredMembers = @()
	# Create an array to store results
	$admins = @()
	$uniqueResults = @()
	# Get members of Protected Users group
	$protectedUsers = Get-ADGroupMember -Identity "Protected Users"

foreach ($group in Get-Content -Path $FileName) {
    # Get the group members
    $groupMembers = Get-ADGroupMember -Server $Server -Identity $group -Recursive | Where-Object {$_.objectClass -eq 'user'}
    #Write-Host $groupMembers
    # Filter users with adminCount equals to 1 and are enabled from the group member

    # Add results to the array
    foreach ($user in $groupMembers) {
	$enabledusers = Get-ADUser -Identity $user.SamAccountName -Server $Server -Properties Enabled
	if ($enabledusers.Enabled -eq $true){
        $admins += $user.SamAccountName}
	else {
	continue
	}
    }
}
#Write-Host $admins.GetType()
# Filter unique users based on SamAccountName
#$uniqueResults = $admins | Select-Object -Unique
#Write-Host $uniqueResults
#foreach ($member in $uniqueResults) {
#    if ($member.DistinguishedName -in $protectedUsers.DistinguishedName) {
#        $filteredMembers += $member                                
#    }
#}
foreach ($admin in $admins){
	if ($uniqueResults -notcontains $admin ){
		$uniqueResults += $admin}
}
#foreach ($member in $uniqueResults) {
#    if ($member -in $protectedUsers.SamAccountName) {
#        $filteredMembers += $member
#    }
#}
$uniqueResults 
#$filteredMembers | Export-Csv -Path "$currentPath\AdminsNotProtected.csv" -NoTypeInformation
}
