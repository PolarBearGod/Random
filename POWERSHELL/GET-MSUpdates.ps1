[Net.ServicePointManager]::SecurityProtocol=[Enum]::ToObject([Net.SecurityProtocolType], 3072)
$ErrorActionPreference= 'silentlycontinue'
$msSecCatalog = "http://go.microsoft.com/fwlink/?LinkId=76054"
$workingdir = "$env:systemroot\temp"
$exeFilePath = "$env:SystemRoot\Temp\mbsacli.exe"
$xmlout = "$env:SystemRoot\Temp\$env:computername-$a-msba.xml"
$a = Get-Date -Format yyyyMMdd-HHmmss
$msSecCatalogCAB = "$workingdir\wsusscn2.cab"
$wusscanDLL = "wusscan.dll"

If (!(Test-Path "$msSecCatalogCAB")) {
    throw "wsusscn2.cab not found. Downloading..."
    $client = new-object System.Net.WebClient
    $client.DownloadFile($msSecCatalog, $msSecCatalogCAB)
    Start-Sleep -Seconds 2
    If (!( Test-Path $exeFilePath)) {
        throw "$exeFilePath not found. "
    }
    else {
        &$exeFilePath /nd /nvc /xmlout /catalog $msSecCatalogCAB 2>&1 | Out-File -Append $xmlout
    }
}

Start-Sleep -Seconds 5

# Remove excess files
Remove-Item -Force $msSecCatalogCAB
Remove-Item -Force $exeFilePath
Remove-Item -Force $workingdir\$wusscanDLL
Remove-Item -Force $workingdir\wsusscn2.cab.dat
Remove-Item -Force $workingdir\msbacli.zip
Remove-Item -Force $workingdir\Get-MSUpdates.ps1
# Remove-Item -Force $xmlout
