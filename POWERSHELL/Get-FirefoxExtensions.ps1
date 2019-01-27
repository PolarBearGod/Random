<#
.SYNOPSIS
Get-FireFoxExtentions.ps1 creates a file of the contents of the FireFox Extensions folder.
Since this directory is plainly readable no other actions are necessary.

This also gets the copy of the contents of the staged folder as well.
#>

$ErrorActionPreference= 'silentlycontinue'
$ext_ids = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\*"
$ext_ids_staged = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions\staged\*"
$export = "$ENV:SYSTEMROOT\Temp\Updates"
$outfile = "$export\$env:COMPUTERNAME-FireFoxExtension.txt"
$Output1 = Get-ChildItem -Name $ext_ids
$Output2 = Get-ChildItem -Name $ext_ids_staged
If (!(test-path "$export"))
{
    New-Item -Name Updates -ItemType Directory -Path "$env:systemroot\Temp" -Force
}
$Output1 | Out-File -Encoding ASCII -Append -FilePath $outfile

# This directory is where Firefox keeps add-ons pending a restart.
Add-Content -Encoding ASCII $outfile '---Stage Directory Contents---'
$Output2 | Out-File -Encoding ASCII -Append -FilePath $outfile
