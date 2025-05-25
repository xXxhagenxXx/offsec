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

function Test-SharePaths {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$SharePaths,  # Accepts an array of SharePaths

        [Parameter(Mandatory=$true)]
        [string]$CsvOutputPath  # Path to output CSV file
    )

    # Initialize a synchronized array to store the results across parallel threads
    $results = [System.Collections.Concurrent.ConcurrentBag[psobject]]::new()

    # Function to check the access of each SharePath
    $checkSharePath = {
        param($SharePath)

        # Initialize access type
        $accessType = "No Access"

        try {
            # Check if the SharePath exists
            if (-not (Test-Path $SharePath)) {
                throw "The share path '$SharePath' does not exist."
            }

            # Test for read access
            $readAccess = $false
            try {
                Get-ChildItem -Path $SharePath | Out-Null
                $readAccess = $true
            }
            catch {
                Write-Host "Read access failed for '$SharePath': $_" -ForegroundColor Red
            }

            # Test for write access
            $writeAccess = $false
            if ($readAccess) {
                try {
                    $testFile = Join-Path -Path $SharePath -ChildPath "NetsyncOffsecTest.tmp"
                    Set-Content -Path $testFile -Value "This is a Netsync Offsec Test." -ErrorAction Stop
                    Remove-Item -Path $testFile -Force
                    $writeAccess = $true
                }
                catch {
                    Write-Host "Write access failed for '$SharePath': $_" -ForegroundColor Red
                }
            }

            # Determine access type
            if ($readAccess -and $writeAccess) {
                $accessType = "Read and Write Access"
            }
            elseif ($readAccess) {
                $accessType = "Read Access Only"
            }
        }
        catch {
            Write-Host "An error occurred for '$SharePath': $_" -ForegroundColor Red
        }

        # Add result to the shared concurrent bag
        $results.Add([pscustomobject]@{
            SharePath  = $SharePath
            AccessType = $accessType
        })
    }

    # Use ForEach-Object with the -Parallel parameter for parallel processing
    $SharePaths | ForEach-Object -Parallel {
        # Run the check function in parallel
        $using:checkSharePath.Invoke($_)
    } -ThrottleLimit 5  # Limit the number of threads (adjust as needed)

    # Output the results to the specified CSV file
    $results | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Force

    Write-Host "Results exported to $CsvOutputPath"
}


function Test-SharePaths {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$SharePaths,  # Accepts an array of SharePaths

        [Parameter(Mandatory=$true)]
        [string]$CsvOutputPath  # Path to output CSV file
    )

    # Initialize an array to store the results
    $results = @()

    # Loop through each SharePath
    foreach ($SharePath in $SharePaths) {
        # Create a variable to store access type
        $accessType = "No Access"

        try {
            # Check if the SharePath exists
            if (-not (Test-Path $SharePath)) {
                throw "The share path '$SharePath' does not exist."
            }

            # Test for read access
            $readAccess = $false
            try {
                Get-ChildItem -Path $SharePath | Out-Null
                $readAccess = $true
            }
            catch {
                Write-Host "Read access failed for '$SharePath': $_" -ForegroundColor Red
            }

            # Test for write access
            $writeAccess = $false
            if ($readAccess) {
                try {
                    $testFile = Join-Path -Path $SharePath -ChildPath "NetsyncOffsecTestFile.tmp"
                    Set-Content -Path $testFile -Value "This is a Netsync Offsec Test File." -ErrorAction Stop
                    Remove-Item -Path $testFile
                    $writeAccess = $true
                }
                catch {
                    Write-Host "Write access failed for '$SharePath': $_" -ForegroundColor Red
                }
            }

            # Determine access type
            if ($readAccess -and $writeAccess) {
                $accessType = "Read and Write Access"
            }
            elseif ($readAccess) {
                $accessType = "Read Access Only"
            }
        }
        catch {
            Write-Host "An error occurred for '$SharePath': $_" -ForegroundColor Red
        }

        # Add the result for this SharePath to the results array
        $results += [pscustomobject]@{
            SharePath  = $SharePath
            AccessType = $accessType
        }
    }

    # Output the results to the specified CSV file
    $results | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Force

    Write-Host "Results exported to $CsvOutputPath"
}

# Example usage: Pass an array of share paths
$sharePaths = @(
    "\\server1\sharedfolder1",
    "\\server2\sharedfolder2",
    "\\server3\sharedfolder3"
)

Test-SharePaths -SharePaths $sharePaths -CsvOutputPath "C:\Path\To\Output.csv"



function Get-UserGroupsAndLocalGroups {
    # Ensure the Active Directory module is imported
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "Active Directory module is not installed or available." -ForegroundColor Yellow
        $ADAvailable = $false
    }
    else {
        $ADAvailable = $true
    }

    # Get the current user's username in the format 'DOMAIN\username'
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $username = $currentUser.Split('\')[-1]  # Extract username
    
    # Output the current user
    Write-Host "Current user: $currentUser" -ForegroundColor Cyan

    # Local Groups
    Write-Host "`n--- Local Group Memberships ---" -ForegroundColor White
    try {
        $localGroups = Get-LocalGroup | ForEach-Object {
            $groupName = $_.Name
            $members = Get-LocalGroupMember -Group $groupName | Where-Object { $_.Name -like "*$username*" }

            if ($members) {
                Write-Host "User '$username' is a member of the local group '$groupName'" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "Error retrieving local group memberships: $_" -ForegroundColor Red
    }

    # Active Directory Groups
    if ($ADAvailable) {
        Write-Host "`n--- Active Directory Group Memberships ---" -ForegroundColor White
        try {
            # Get the current user's AD object, retrieving group memberships
            $user = Get-ADUser -Identity $username -Properties MemberOf
            
            if ($user.MemberOf) {
                # Enumerate all AD groups
                $adGroups = $user.MemberOf | ForEach-Object {
                    (Get-ADGroup -Recursive $_).Name
                }

                # Output the AD groups
                $adGroups | ForEach-Object { Write-Host "User '$currentUser' is a member of the AD group '$_'." -ForegroundColor Green }
            }
            else {
                Write-Host "User '$currentUser' is not a member of any AD groups." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "Error retrieving Active Directory groups for user '$currentUser': $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Skipping AD group check since the Active Directory module is not available." -ForegroundColor Yellow
    }
}

# Example usage
Get-UserGroupsAndLocalGroups
