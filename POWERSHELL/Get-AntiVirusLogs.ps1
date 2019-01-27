function Get-AntiVirusLogs {
    <#
.SYNOPSIS
  Collect AV Data to parse for threats
.DESCRIPTION
  This script was created in the hopes to collect from as many AV sources as possible,
  to then dump key log sources into a zip. The idea is during a threat hunting campaign,
  the AV solution may have caught the behavior of previous threats on the machine.
.PARAMETER CSVFilePath
    Final destination where contents will be zipped and stored.
.NOTES
  Version:        1.3
  Author:         Bryan Bowie
  Creation Date:  29June2018
  Purpose/Change: Initial script development.
                  Changed Zipping function.
                  Corrected spelling mistakes
                  Added Example usage of main function 'Get-AntiVirusLogs'

Currently Support the following AntiVirus Vendors and their locations:
    Windows 7 Defender
    Windows 10 Defender (via PowerShell)
    Avast
    AVG
    Cisco AMP
    McAfee
    Sophos
    Vipre
    Fortinet

Future Support:
    Norton
    Kaspersky
    Comodo
    Webroot*
    ESET*
    Trend Micro*
    Bitdefender*
    Checkpoint ZoneAlarm*
    ClamAV*
    F-Secure*

.EXAMPLE
  Get-AntiVirusLogs -CSVFilePath "$env:systemroot\Temp\Output"
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]$CSVFilePath
    )

    #---------------------------------------------------------[Variables]--------------------------------------------------------
    $ErrorActionPreference = "SilentlyContinue"
    $stage = "$ENV:SYSTEMROOT\Temp\Stage"
    $a = Get-Date -Format yyyyMMdd-HHmmss
    $OSVersion = [System.Environment]::OSVersion.Version.Major

    If (test-path "$CSVFilePath") {
        Remove-Item -Force -Recurse -Path $CSVFilePath
        New-Item -ItemType Directory -Path "$CSVFilePath" -Force
    }
    else {
        New-Item -ItemType Directory -Path "$CSVFilePath" -Force
    }

    If (test-path "$Stage") {
        Remove-Item -Force -Recurse -Path $stage
        New-Item -Name Stage -ItemType Directory -Path "$env:systemroot\Temp" -Force
    }
    else {
        New-Item -Name Stage -ItemType Directory -Path "$env:systemroot\Temp" -Force
    }

    Function ZipFiles {
        <#
       .SYNOPSIS
              A function to zip or unzip files.
       .DESCRIPTION
              This function has 3 possible uses.
              1) Zip a folder or files and save the zip to specified location.
              2) Unzip a zip file to a specified folder.
              3) Unzip a zip file and delete the original zip when complete.       
       .PARAMETER ZipPath
              The full path of the file to unzip or the full path of the zip file to be created.
       .PARAMETER FolderPath
              The path to the files to zip or the path to the directory to unzip the files to.
       .PARAMETER Unzip
              If $true the function will perform an unzip instead of a zip
       .PARAMETER DeleteZip
              If set to $True the zip file will be removed at then end of the unzip operation.
       .EXAMPLE
              PS C:\> ZipFiles -ZipPath 'C:\Windows\Temp\ziptest.zip' -FolderPath 
              PS C:\> ZipFiles -ZipPath 'C:\Windows\Temp\ziptest.zip' -FolderPath 'C:\Windows\Temp\ZipTest' -Unzip $true
              PS C:\> ZipFiles -ZipPath 'C:\Windows\Temp\ziptest.zip' -FolderPath 'C:\Windows\Temp\ZipTest' -Unzip $true -DeleteZip $True
       .NOTES
              Additional information about the function.
        #>
        [CmdletBinding(DefaultParameterSetName = 'Zip')]
        param
        (
            [Parameter(ParameterSetName = 'Unzip')]
            [Parameter(ParameterSetName = 'Zip',
                Mandatory = $true,
                Position = 0)]
            [ValidateNotNull()]
            [string]$ZipPath,
            [Parameter(ParameterSetName = 'Unzip')]
            [Parameter(ParameterSetName = 'Zip',
                Mandatory = $true,
                Position = 1)]
            [ValidateNotNull()]
            [string]$FolderPath,
            [Parameter(ParameterSetName = 'Unzip',
                Mandatory = $false,
                Position = 2)]
            [ValidateNotNull()]
            [bool]$Unzip,
            [Parameter(ParameterSetName = 'Unzip',
                Mandatory = $false,
                Position = 3)]
            [ValidateNotNull()]
            [bool]$DeleteZip
        )
        Log-Message "Entering Zip-Actions Function."
        switch ($PsCmdlet.ParameterSetName) {
            'Zip' {
                If ([int]$psversiontable.psversion.Major -lt 3) {
                    Log-Message "Step 1"
                    New-Item $ZipPath -ItemType file
                    $shellApplication = new-object -com shell.application
                    $zipPackage = $shellApplication.NameSpace($ZipPath)
                    $files = Get-ChildItem -Path $FolderPath -Recurse
                    Log-Message "Step 2"
                    foreach ($file in $files) {
                        $zipPackage.CopyHere($file.FullName)
                        Start-sleep -milliseconds 500
                    }
                    Log-Message "Exiting Zip-Actions Function."
                    break           
                }
                Else {
                    Log-Message "Step 3"
                    Add-Type -assembly "system.io.compression.filesystem"
                    $Compression = [System.IO.Compression.CompressionLevel]::Optimal
                    [io.compression.zipfile]::CreateFromDirectory($FolderPath, $ZipPath, $Compression, $True)
                    Log-Message "Exiting Zip-Actions Function."
                    break
                }
            }
            'Unzip' {
                $shellApplication = new-object -com shell.application
                $zipPackage = $shellApplication.NameSpace($ZipPath)
                $destinationFolder = $shellApplication.NameSpace($FolderPath)
                $destinationFolder.CopyHere($zipPackage.Items(), 20)
                Log-Message "Exiting Unzip Section"
            }
        }
    }

    function Clean-Stage{
        Get-ChildItem -Path "$Stage" -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
    }


    # Windows 7+
    If (test-path "$env:ProgramData\Microsoft\Windows Defender\") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\Microsoft\Windows Defender\Support\*.log" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-WinDefender-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # Windows 10
    If ($OSVersion -eq "10") {
        Get-MpThreat | Select-Object * | Export-Csv -NoTypeInformation -Path $stage\$env:computername-Win10DT-$a.csv
        Get-MpThreatDetection | Select-Object * | Export-Csv -NoTypeInformation -Path $stage\$env:computername-Win10DTD-$a.csv
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-Win10Defender-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # Avast
    If (test-path "$env:ProgramData\Avast Software\") {
        Copy-Item -Force -Path "$env:ProgramData\Avast Software\Avast\Log\Cleaner.log" -Destination "$Stage"
        Copy-Item -Force -Path "$env:ProgramData\Avast Software\Avast\Log.db" -Destination "$Stage"
        Copy-Item -Recurse -Force -Path "$env:ProgramData\Avast Software\Avast\Report\*.*" -Destination "$Stage"
        Copy-Item -Force -Path "$env:ProgramData\Avast Software\Avast\Chest\index.xml" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-Avast-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # McAfee
    If (test-path "$env:ProgramData\McAfee\") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\McAfee\VirusScan\logs\*.*" -Destination "$Stage"
        Copy-Item -Recurse -Force -Path "$env:ProgramData\McAfee\VirusScan\Quarantine\Quarantine.db" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-McAfee-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # Sophos
    If (test-path "$env:ProgramData\sophos") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\sophos\sophos anti-virus\logs\*.*" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-Sophos-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # AMP
    If (test-path "$env:ProgramData\Sourcefire") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\Sourcefire\FireAMP\*.*" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-CiscoAMP-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }
    If (test-path "$env:ProgramData\Cisco\AMP") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\Cisco\AMP\*.*" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-CiscoAMP-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # Vipre
    If (test-path "$env:ProgramData\VIPRE") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\VIPRE\Quarantine\*.*" -Destination "$Stage"
        Copy-Item -Recurse -Force -Path "$env:ProgramData\VIPRE\History\*.*" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-VIPRE-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    # AVG
    If (test-path "$env:ProgramData\AVG") {
        Copy-Item -Recurse -Force -Path "$env:ProgramData\AVG\Antivirus\report\*.*" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-AVG-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

    #Fortinet
    If (test-path "$env:programfiles\Fortinet") {
        Copy-Item -Recurse -Force -Path "$env:programfiles\Fortinet\FortiClient\logs\*.*" -Destination "$Stage"
        # Copy-Item -Force -Path "$env:programfiles\Fortinet\FortiClient\logs\fclog.dat" -Destination "$Stage"
        ZipFiles -ZipPath "$CSVFilePath\$env:computername-Fortinet-$a.zip" -FolderPath "$Stage"
        Clean-Stage
    }

Remove-Item -Recurse -Force "$Stage"
    
}
