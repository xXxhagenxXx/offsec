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
#$sharePaths = @(
#    "\\server1\sharedfolder1",
#    "\\server2\sharedfolder2",
#    "\\server3\sharedfolder3"
#)

#Test-SharePaths -SharePaths $sharePaths -CsvOutputPath "C:\Path\To\Output.csv"
