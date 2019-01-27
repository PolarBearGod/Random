# You can skip a mass upload by using the following variables
# instead of the ones used below. Comment out the top three
# lines and change the $Computer variable to: 
# $computer = "." 
# This will select the local host. If you would like to 
# specify one host, replace the dot with the host name 
# (do not include the FQDN.

$computerlist = "C:\ServerList.txt"
$outputlist = "C:\ServerList_Completed.txt"
$errorlist = "C:\ServerList_Errors.txt"

# This is the set up for pulling the host names from the text file
$Computers = Get-Content $computerlist

# Include the computer name for output reasons
Get-Content env:computername

# Loop through each host name in the 
foreach ($computer in $computers)
{
    # Obtain the user profile(s) of the hostname
    $Profiles = gwmi win32_userprofile -ComputerName $Computer

    # Empty Array of Profiles
    $colProfiles = @()

    # For each profile found, loop through and create the following information
    foreach ($Profile in $Profiles)
    {
    Try {
    # Get the SID of the account who had logged in
    $UserSID = New-Object System.Security.Principal.SecurityIdentifier($Profile.SID)

    # Get the Domain\Username details from the SID
    $User = $UserSID.Translate([System.Security.Principal.NTAccount])

    # Get the DateTime values
    $Time = ([WMI] '').ConvertToDateTime($Profile.LastUseTime)
    $LogonTime = $Time.ToShortTimeString()
    $LogonDate = $Time.ToShortDateString()

    # Create an Object with the $User, $LogonDate &amp; $LogonTime properties
    $LastLogons = New-Object system.object
    $LastLogons | Add-Member -MemberType noteproperty -Name UserName -Value $User
    $LastLogons | Add-Member -MemberType noteproperty -Name LastLogonDate -Value $LogonDate
    $LastLogons | Add-Member -MemberType noteproperty -Name LastLogonTime -Value $LogonTime

    # Populate the properties of the $LastLogons object with User, Logon Date and Time from the profiles
    $colProfiles += $LastLogons
    }

    # Catch this error and dump it into the list. Can add more later.
    Catch [System.Exception]
    {
    "Cannot query a local account's SID against the Domain"
        $computer | out-file -append $errorlist
    }

    Finally {}
    }

    # Formatting of the array and take results and put into output text file
    $colProfiles | ft -AutoSize
    $colProfiles | out-file -append $outputlist
}
