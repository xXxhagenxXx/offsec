
# Global variables
$currentPath = Get-Location
$adminGroups = @("Administrators","Domain Admins","Server Operators","Schema Admins","Backup Operators","Enterprise Admins","Account Operators","Cert Publishers","DHCP Administrators","DNSAdmins","Print Operators","Replicator")
echo $adminGroups > "$currentPath\Admin groups.txt"
$adminGroups = "$currentPath\Admin groups.txt"

<#
.SYNOPSIS
    Function used to gather administrative accounts that can be delegated.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that are enabled and don't have the flag "This account is sensitive and cannot be delegated". Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    AdminAccountCanBeDelegated -FileName groups.txt -Domain example.com
.EXAMPLE
    AdminAccountCanBeDelegated -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function AdminAccountCanBeDelegated {
    param( $FileName = $adminGroups,$Domain)
    $results = @()
    foreach($content in Get-Content -Path $FileName){
        $results += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain -AllowDelegation | Where-Object {($_.userAccountControl -band 2) -eq 0}} | Select-Object -Unique SamAccountName
    }
    $results | Select-Object -Unique samaccountname | Export-Csv -Path "$currentPath\Admins that can be delegated.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function that gathers objects that have been inactive for 6 months or more.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users and computers recursively that are enabled and have been inactive for 6 months or more. Results are exported to individually to CSV files.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    inactiveObjects -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function inactiveObjects {
    param($Domain)
    $inactiveUsers = Get-NetUser -Domain $Domain | Where-Object { ($_.LastLogonTimeStamp -lt (Get-Date).AddMonths(-6)) -and ($_.useraccountcontrol -notmatch 'ACCOUNTDISABLE') -and ($_.LastLogonTimeStamp -ne $NULL)} | Select-Object -Unique SamAccountName
    $inactiveUsers | Export-csv -Path "$currentPath\Inactive users.csv" -NoTypeInformation
    $inactiveComputers = Get-NetComputer -Domain $Domain | Where-Object { ($_.LastLogonTimeStamp -lt (Get-Date).AddMonths(-6)) -and ($_.useraccountcontrol -notmatch 'ACCOUNTDISABLE') -and ($_.LastLogonTimeStamp -ne $NULL)} | Select-Object cn
    $inactiveComputers | Export-csv -Path "$currentPath\Inactive computers.csv" -NoTypeInformation
    if (-not (Test-Path "$currentPath\Inactive Objects")) {
        New-Item -ItemType Directory -Path "$currentPath\Inactive Objects"
    }
    Move-Item "$currentPath\Inactive users.csv" -Destination "$currentPath\Inactive Objects" -Force
    Move-Item "$currentPath\Inactive computers.csv" -Destination "$currentPath\Inactive Objects" -Force
}

<#
.SYNOPSIS
    Function used to gather administrative accounts that are inactive.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that are enabled and have been inactive for 90 days or more. Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    inactiveAdmins -FileName groups.txt -Domain example.com
.EXAMPLE
    inactiveAdmins -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function inactiveAdmins {
    param($FileName = $adminGroups,$Domain)
    $results = @()
    foreach($content in Get-Content -Path $FileName){
        $results += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity  $_.MemberName -Domain $Domain | Where-Object {($_.lastlogontimestamp -lt (Get-Date).AddDays(-90)) -and ($_.useraccountcontrol -notmatch 'ACCOUNTDISABLE') -and ($_.LastLogonTimeStamp -ne $NULL)}} | Select-Object -Unique SamAccountName
    }
    $results | Select-Object -Unique samaccountname | Export-Csv -Path "$currentPath\Inactive admins.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function used to gather administrative accounts that can have non-expiring passwords.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that are enabled and their passwords don't expire. Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    dontExpirePasswordAdmins -FileName groups.txt -Domain example.com
.EXAMPLE
    dontExpirePasswordAdmins -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function dontExpirePasswordAdmins {
    param($FileName = $adminGroups,$Domain)
    $results = @()
    foreach($content in Get-Content -Path $FileName){
        $results += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.useraccountcontrol -match 'DONT_EXPIRE_PASSWORD' -and ($_.useraccountcontrol -band 2) -eq 0)}} | Select-Object SamAccountName
    }
    $results | Select-Object -Unique samaccountname | Export-Csv -Path "$currentPath\Admins with never expiring passwords.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function used to gather administrative accounts that have old passwords.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that are enabled and have a password that are 3 years old or more. Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    oldPasswordsAdmins -FileName groups.txt -Domain example.com
.EXAMPLE
    oldPasswordsAdmins -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function oldPasswordsAdmins {
    param($FileName = $adminGroups,$Domain)
    $results = @()
    foreach($content in Get-Content -Path $FileName){
        $results += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.pwdlastset -lt (Get-Date).AddMonths(-36) -and ($_.useraccountcontrol -band 2) -eq 0)}} | Select-Object SamAccountName
    }
    $results | Select-Object -Unique samaccountname | Export-Csv -Path "$currentPath\Admins old passwords.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function that gathers objects with wrong primary groups set.

.DESCRIPTION
    This function gathers all users and computers that are enabled and have uncommon primary groups set. Results are exported to a CSV file.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    wrongPrimaryGroups -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function wrongPrimaryGroups {
    param($Domain)
    $users = Get-NetUser -Domain $Domain | Where-Object {$_.primarygroupid -notin @(512, 513, 514) -and ($_.useraccountcontrol -band 2) -eq 0} | Select-Object SamAccountName, primarygroupid
    $computers = Get-NetComputer -Domain $Domain | Where-Object {$_.primarygroupid -notin @(515, 516) -and ($_.useraccountcontrol -band 2) -eq 0} | Select-Object SamAccountName, primarygroupid
    $allObjects = $users + $computers
    $allObjects | Export-csv -Path "$currentPath\Wrong primary groups.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function used to gather administrative accounts that are not in the Protected Users group.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that are not part of the Protected Users group. Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    notInProtectedUsersGroup -FileName groups.txt -Domain example.com
.EXAMPLE
    notInProtectedUsersGroup -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function notInProtectedUsersGroup {
    param($FileName = $adminGroups,$Domain)
    $adminUsers = @()
    foreach($content in Get-Content -Path $FileName){
        $adminUsers += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.useraccountcontrol -band 2) -eq 0}} | Select-Object -Unique SamAccountName
        }
    $protectedUsers = Get-NetGroupMember -Identity "Protected Users" -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.useraccountcontrol -band 2) -eq 0}} | Select-Object SamAccountName
    if ($protectedUsers -ne $null){
            $usersNotInProtectedGroup = Compare-Object -ReferenceObject $adminUsers -DifferenceObject $protectedUsers | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty SamAccountName
        }
    else {
            $usersNotInProtectedGroup = $adminUsers
        }
    $usersNotInProtectedGroup | Select-Object -Unique samaccountname | Export-Csv -Path "$currentPath\Admins not in the protected users group.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function that gathers users that belong to the schema admin group.

.DESCRIPTION
    This function gathers all users that are enabled and are part of the schema admins group. Results are exported to a CSV file.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    schemaAdmins -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function schemaAdmins {
    param($Domain)
    $results = Get-NetGroupMember -Identity "Schema Admins" -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.useraccountcontrol -band 2) -eq 0}} | Select-Object -Unique SamAccountName
    $results | Export-Csv -Path "$currentPath\Schema admin members.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function used to gather non administrative accounts that have the admincount flag set.

.DESCRIPTION
    The function iterates through a list of admin groups and gathers all users recursively that have the admincount flag set. Results are exported to a CSV file.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    admincountUsers -FileName groups.txt -Domain example.com
.EXAMPLE
    admincountUsers -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function admincountUsers {
    param($FileName = $adminGroups, $Domain)
    $UniqueUsers = @()
    $adminUsers = @()
    foreach($content in Get-Content -Path $FileName){
        $adminUsers += Get-NetGroupMember -Identity $content -Domain $Domain -Recurse | %{Get-NetUser -Identity $_.MemberName -Domain $Domain | Where-Object {($_.useraccountcontrol -band 2) -eq 0}} | Select-Object SamAccountName | Sort-Object
        }
    $admincountAccounts = Get-NetUser -Domain $Domain | Where-Object { $_.admincount -eq 1 -and ($_.useraccountcontrol -band 2) -eq 0} | Select-Object samaccountname | Sort-Object
    if ($admincountAccounts -ne $null){
        foreach ($account in $admincountAccounts) {
            $samAccountName = $account.SamAccountName
            if ($samAccountName -notin $adminUsers.SamAccountName) {
                $UniqueUsers += $account
            }
        }
        $UniqueUsers | Export-Csv -Path "$currentPath\Users with admincount set.csv" -NoTypeInformation
    }
    else {
        $admincountAccounts = @()
        echo "There are no accounts with admincount"
    }
}

<#
.SYNOPSIS
    Function that gathers obsolete operating systems across a domain environment.

.DESCRIPTION
    This function gathers all computers that are enabled and are using obsolete operating systems. Results are exported to a CSV file.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    obsoleteOs -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function obsoleteOs {
    param($Domain)
    $computers = @()
    $operatingSystems = @("Windows 7","Windows xp","Windows 8","Windows Server 2008")
    $rawOutput = Get-NetComputer -Domain $Domain
    foreach($machine in $rawOutput){
        foreach($i in $operatingSystems){
            if(-not ($machine.useraccountcontrol -band 2) -and $machine.operatingsystem -like "*$i*"){
                $computers += $machine | Select-Object cn,operatingsystem
            }
        }
    }
    $computers | Export-Csv -Path "$currentPath\Obsolete operating systems.csv" -NoTypeInformation
}

<#
.SYNOPSIS
    Function that gathers objects that supports DES for Kerberos authentication.

.DESCRIPTION
    The function will enumerate Active Directory objects that supports DES for Kerberos authentication.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    DESObjects -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function DESObjects {
    param($Domain)
    
    $DESUsers = Get-NetUser -Domain $Domain | Where-Object { ($_.'msDS-SupportedEncryptionTypes' -ne $NULL) -and (($_.'msDS-SupportedEncryptionTypes' % 4) -ne 0 ) -and ($_.useraccountcontrol -notmatch 'ACCOUNTDISABLE') } | select samaccountname
    $DESUsers | Export-csv -Path "$currentPath\DES users.csv" -NoTypeInformation
    $DESComputers = Get-NetComputer -Domain $Domain | Where-Object { ($_.'msDS-SupportedEncryptionTypes' -ne $NULL) -and (($_.'msDS-SupportedEncryptionTypes' % 4) -ne 0 ) -and ($_.useraccountcontrol -notmatch 'ACCOUNTDISABLE') } | select samaccountname
    $DESComputers | Export-csv -Path "$currentPath\DES computers.csv" -NoTypeInformation
    if (-not (Test-Path "$currentPath\DES Objects")) {
        New-Item -ItemType Directory -Path "$currentPath\DES Objects"
    }
    Move-Item "$currentPath\DES users.csv" -Destination "$currentPath\DES Objects" -Force
    Move-Item "$currentPath\DES computers.csv" -Destination "$currentPath\DES Objects" -Force
}

<#
.SYNOPSIS
    Function that gathers objects that can be set without a password if it has the flag "PASSWD_NOTREQD" set as "True" in the "useraccountcontrol" attribute.

.DESCRIPTION
    The function will enumerate Active Directory objects that has the flag "PASSWD_NOTREQD" set as "True".
    
.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    passwdnotreqdObjects -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>

function passwdnotreqdObjects {
    param($Domain)
    $passwd_notreqdUsers = Get-NetUser -Domain $Domain | Where-Object {$_.useraccountcontrol -notmatch 'ACCOUNTDISABLE' -and $_.useraccountcontrol -match 'PASSWD_NOTREQD'} | Select-Object -Unique SamAccountName
    $passwd_notreqdUsers | Export-csv -Path "$currentPath\Password NotRequired users.csv" -NoTypeInformation
    $passwd_notreqdComputers = Get-NetComputer -Domain $Domain | Where-Object {$_.useraccountcontrol -notmatch 'ACCOUNTDISABLE' -and $_.useraccountcontrol -match 'PASSWD_NOTREQD'} | Select-Object -Unique SamAccountName
    $passwd_notreqdComputers | Export-csv -Path "$currentPath\Password NotRequired computers.csv" -NoTypeInformation
    if (-not (Test-Path "$currentPath\Password NotRequired Objects")) {
        New-Item -ItemType Directory -Path "$currentPath\Password NotRequired Objects"
    }
    Move-Item "$currentPath\Password NotRequired users.csv" -Destination "$currentPath\Password NotRequired Objects" -Force
    Move-Item "$currentPath\Password NotRequired computers.csv" -Destination "$currentPath\Password NotRequired Objects" -Force
}

<#
.SYNOPSIS
    Function that runs all the other functions within this script.

.DESCRIPTION
    This function executes all the functions within the script one at a time.

.PARAMETER FileName
    Optional parameter that has a default value for a list of admin groups. The parameter takes a text file containing a list of administrative groups.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    allChecks -FileName groups.txt -Domain example.com
.EXAMPLE
    allChecks -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>

function allChecks {
    param($Domain,$FileName = $adminGroups)
    AdminAccountCanBeDelegated -Domain $Domain -FileName $FileName
    inactiveObjects -Domain $Domain
    inactiveAdmins -Domain $Domain -FileName $FileName
    dontExpirePasswordAdmins -Domain $Domain -FileName $FileName
    oldPasswordsAdmins -Domain $Domain -FileName $FileName
    wrongPrimaryGroups -Domain $Domain
    notInProtectedUsersGroup -Domain $Domain -FileName $FileName
    schemaAdmins -Domain $Domain
    admincountUsers -Domain $Domain -FileName $FileName
    obsoleteOs -Domain $Domain
    DESObjects -Domain $Domain
    passwdnotreqdObjects -Domain $Domain
}
