'Silent Runners.vbs -- find out what starts up with Windows!
'(compatible with Windows 95/98/Millennium/NT 4.0 Workstation/NT 4.0 Server/2000/2000 Server/
'and with 32 & 64-bit versions of XP/Server 2003/Vista/7/8/10/Server 2008)
'
'DO NOT REMOVE THIS HEADER!
'
'Copyright Andrew ARONOFF 15 April 2018, http://www.silentrunners.org/
'This script is provided without any warranty, either express or implied
'It may not be copied or distributed without permission
'
'** YOU RUN THIS SCRIPT AT YOUR OWN RISK! **  (END OF HEADER)

Option Explicit

Dim strRevNo : strRevNo = "72"

Public flagTest : flagTest = False  'True if in testing mode
'flagTest = True  'Uncomment to put in testing mode
Public arSecTest : arSecTest = Array()  'array of section numbers to test

'This script is divided into 36 sections.

'malware launch points:
' registry keys (1-17, 19, 22)
' INI/INF-files (20-21, 23)
' folders (24-25)
' enabled scheduled tasks (26)
' Winsock2 service provider DLLs (27)
' IE toolbars, explorer bars, extensions (28)
' started services (32)
' safe mode drivers & services (33)
' accessibility tools (34)
' keyboard driver filters (35)
' print monitors (36)

'hijack points:
' System/Group Policies (18)
' prefixes for IE URLs (29)
' misc IE points (30)
' HOSTS file (31)

'Output is suppressed if deemed normal unless the -all parameter is used
'Section 23 is skipped unless the -supp/-all parameters are used or
'the first message box is answered "No" and the next message box "Yes"

' 1. HKCU/HKLM/HKLM-WOW... Run
'    HKCU/HKLM... RunOnce/RunOnce\Setup/RunOnceEx
'    HKLM... RunServices/RunServicesOnce
'    HKCU/HKLM... Policies\Explorer\Run
' 2. HKLM/HKLM-WOW... Active Setup\Installed Components
'    HKCU/HKCU-WOW... Active Setup\Installed Components
'     (StubPath <> "" And HKLM version # > HKCU version #)
' 3. HKLM/HKLM-WOW... Explorer\Browser Helper Objects
' 4. HKCU/HKLM/HKLM-WOW... Explorer\ShellIconOverlayIdentifiers
' 5. HKCU/HKLM/HKLM-WOW... Explorer\ShellServiceObjects
' 6. HKCU/HKLM/HKLM-WOW... Shell Extensions\Approved
' 7. HKLM/HKLM-WOW... Explorer\DeviceNotificationCallbacks/SharedTaskScheduler/ShellExecuteHooks
' 8. HKCU/HKLM/HKLM-WOW... ShellServiceObjectDelayLoad
' 9. HKCU/HKLM/HKLM-WOW... Command Processor\AutoRun
'    HKCU... Policies\System\Shell (W2K/WXP/WVa/Wn7 only)
'    HKCU... Windows\load & run
'    HKLM/HKLM-WOW... Windows\AppInit_DLLs
'    HKLM... Windows NT... Aedebug
'    HKCU/HKLM... Windows NT... Winlogon\Shell
'    HKLM... Windows NT... Winlogon\Userinit, System, Ginadll, Taskman, VmApplet
'    HKLM... Control\ServiceControlManagerExtension
'    HKLM... Control\BootVerificationProgram\ImagePath
'    HKLM... Control\Lsa\Authentication Packages
'    HKLM... Control\Lsa\Notification Packages
'    HKLM... Control\Lsa\Security Packages
'    HKLM... Control\SafeBoot\Option\UseAlternateShell
'    HKLM... Control\SafeBoot\AlternateShell
'    HKLM... Control\SecurityProviders\SecurityProviders
'    HKLM... Control\Session Manager\BootExecute
'    HKLM... Control\Session Manager\Execute
'    HKLM... Control\Session Manager\SetupExecute
'    HKLM... Control\Session Manager\WOW\cmdline, wowcmdline
'10. HKLM... Authentication\Credential Provider Filters/Credential Providers/PLAP Providers
'11. HKLM... Windows NT... Winlogon\Notify subkey DLLName values
'12. HKLM... Windows NT... Winlogon\GPExtensions subkey GUIDs
'13. HKLM/HKLM-WOW... Windows NT... Image File Execution Options ("Debugger" values)
'14. HKCU/HKLM... Policies... Startup/Shutdown, Logon/Logoff scripts (W2K/WXP/WVa/Wn7)
'15. HKCU/HKLM PROTOCOLS\Filter & PROTOCOLS\Handler
'16. Context menu shell extensions
'17. HKCU/HKLM executable file type (bat/cmd/com/exe/hta/pif/scr)
'18. System/Group Policies
'19. Enabled Wallpaper & Screen Saver
'20. WIN.INI load/run, SYSTEM.INI shell/scrnsave.exe, WINSTART.BAT, IniFileMapping
'21. AUTORUN.INF in root directory of local fixed disks
'22. HKLM... Explorer\AutoplayHandlers\Handlers
'23. DESKTOP.INI in any local fixed disk directory (section skipped by default)
'24. Startup Directories
'25. Windows Sidebar Gadgets
'26. Enabled Scheduled Tasks
'27. Winsock2 Service Provider DLLs
'28. Internet Explorer Toolbars, Explorer Bars, Extensions
'29. Internet Explorer URL Prefixes
'30. Misc. IE Hijack Points
'31. HOSTS file
'32. Started Services
'33. Safe Mode Drivers & Services
'34. Accessibility Tools
'35. Keyboard Driver Filters
'36. Print Monitors

'Configuration Detection Section

' Dim (123)
' FileSystemObject creation error (143)
' CScript/WScript (173)
' Dim (202)
' GetFileVersion(WinVer.exe) (VBScript 5.1) (336)
' WMI (388)
' OS version (419)
' bitness (522)
' WVa/Wn7 relaunch with admin rights (592)
' command line arguments (636)
' supplementary search MsgBox (714)
' startup Popup (751)
' CreateTextFile error (780)
' output file header (818)

Dim Wshso : Set Wshso = WScript.CreateObject("WScript.Shell")
Dim WshoArgs : Set WshoArgs = WScript.Arguments
Dim oNetwk : Set oNetwk = WScript.CreateObject("WScript.Network")
Dim oShellApp
Dim intErrNum, intMB, intMB1  'Err.Number, MsgBox return value x 2
Dim strURL  'download URL
Dim strflagTest : strflagTest = ""
Dim flagOut

'constants
Const DQ = """", SP = " ", BS= "\", HKCU = &H80000001, HKLM = &H80000002, KQV = &H1, KSV = &H2
Const strHKLM = "HKLM", strHKCU = "HKCU"
Const REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, REG_MULTI_SZ=7, REG_QWORD = 11
Const REG_SZ_NO_CN=9  'create this reg value type to avoid CoName
                      'search for strings that are not file names
Const MS = " [MS]", LBr = "{"
Const IWarn = "<<!>> ", HWarn = "<<H>> "
Const SysFolder = 1, WinFolder = 0
Const LIP = "..."  'elLIPsis

On Error Resume Next
 Dim Fso : Set Fso = CreateObject("Scripting.FileSystemObject")
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

If intErrNum <> 0 Then

 strURL = "http://bit.ly/JIZp7"

 intMB = MsgBox (DQ & "Silent Runners" & DQ &_
  " cannot access file services critical to" & vbCRLF &_
  "proper script operation." & vbCRLF & vbCRLF &_
  "If you are running Windows XP, make sure that the" &_
  vbCRLF & DQ & "Cryptographic Services" & DQ &_
  " service is started." & vbCRLF & vbCRLF &_
  "You can also try reinstalling the latest version of the MS" &_
  vbCRLF & "Windows Script Host." & vbCRLF & vbCRLF &_
  "Press " & DQ & "OK" & DQ & " to direct your browser to " &_
  "the download site or" & vbCRLF & Space(10) & DQ & "Cancel" &_
  DQ & " to quit.", vbOKCancel + vbCritical, _
  "Can't access the FileSystemObject!")

  'if dl wanted now, send browser to dl site
 If intMB = 1 Then Wshso.Run strURL

 WScript.Quit

End If

'determine whether output is via MsgBox/PopUp or Echo
If InStr(LCase(WScript.FullName),"wscript.exe") > 0 Then
 flagOut = "W"  'WScript
ElseIf InStr(LCase(WScript.FullName),"cscript.exe") > 0 Then
 flagOut = "C"  'CScript
Else  'echo and continue if it works
 flagOut = "C"  'assume CScript-compatible
 WScript.Echo "Neither " & DQ & "WSCRIPT.EXE" & DQ & " nor " &_
  DQ & "CSCRIPT.EXE" & DQ & " was detected as " &_
  "the script host." & vbCRLF & DQ & "Silent Runners" & DQ &_
  " will assume that the script host is CSCRIPT-compatible and will" & vbCRLF &_
  "use WScript.Echo for all messages."
End If  'script host

If flagTest Then

 strflagTest = "TEST "

 If flagOut = "W" Then
  Wshso.Popup "Silent Runners is in testing mode.",1, _
      "Testing, testing, 1-2-3...", vbOKOnly + vbExclamation
 Else
  WScript.Echo "Silent Runners is in testing mode." & vbCRLF
 End If  'flagOut?

End If  'flagTest?

'arrays
'Run keys/names, keys, sub-keys, value type, SecurityProviders, Protocol filters,
'values, script arguments copy
Dim arRunKeys, arNames, arKeys, arSubKeys, arType, arSP(), arFilter(), arValues, arArgsCopy()
Dim arSK, arSKk, arSKi  'dictionary, keys, items
'found CLSID InprocServer32 DLLs dynamic array
Public arIPSDLL()
'allowed CLSIDs & IPSDLLs dynamic key arrays, dynamic Explorer sub-keys
Dim arAllowedCLSID(), arAllowedDlls(), arExpSubKeys()
'Sub-Directory DeskTop.Ini array, Sub-Directory Error array, Error array
'Recognized GP names, allowed GP names, accessibility tools
Dim arSUFN, arSUFDN  'startup folder names/display names
Public arSDDTI(), arSDErr(), arErr(), arRecNames(), arAllowedNames(), arAcc()
'hive array
Public arHives(1,1)
arHives(0,0) = "HKCU" : arHives(1,0) = "HKLM"
arHives(0,1) = &H80000001 : arHives(1,1) = &H80000002

'counters
Dim i, j, k, ii, jj, kk, intKey  'counters x 7
'DeskTop.Ini counter, Error counter x 2, Classes data Hive counter
Public ctrArDTI, ctrArErr, ctrErr, ctrCH
Public intCnt  'counter
Public ctrFo : ctrFo = 0 'folder counter
Public intSection : intSection = 0  'section counter

'objects
Dim colOS, oOS  'OS collection/object
Public oReg  'WMI registry object
Dim colDisks  'hard disk collection
'startup folder file, startup file shortcut, startup folder
Dim oSUFi, oSUSC, oSUF
Dim oTempFi  'temp file object
Dim oRoot  'drive root directory
Dim oOFFo  'output file folder

'string variables
Public strOS : strOS = "Unknown"
Public strOSSS : strOSSS = "Unknown"  'OS SubSet
Public strOSLong : strOSLong = "Unknown"
Public strPgmFilesDir : strPgmFilesDir = Wshso.ExpandEnvironmentStrings("%PROGRAMFILES%")
Public strFPWF : strFPWF = Fso.GetSpecialFolder(WinFolder).Path  'FullPathWindowsFolder
Public strFPSF : strFPSF = Fso.GetSpecialFolder(SysFolder).Path  'FullPathSystemFolder
Dim strSysVer  'Winver.exe version number
Dim strArgUAC  'argument passed with elevated privileges
'temp directory file name, temp file contents, temp strings x 3
Dim strTempFN, strTempFC, strTemp, strTemp1, strTemp2
Dim strArgs : strArgs = ""  'concatenated script arguments
'HKCU/HKLM CLSID Lower Limit, default is HKLM for OS > NT4
'key array member x 2
Dim strMemKey, strMemSubKey
'values x 9
Dim strValue, strValue1, strValue2, strValue3, strValue4, strValue5, strValue6
Dim strVal, strCmd, strIPSDLL, strHashValue
'name, single character, array member, temp var
Dim strName, strChr, strArMember, strTmp, strTmp2
'ProgID value, context menu shell extension class/handler/allowed DLLs
Dim strProgID, strClass, strHandler, strAllowedDlls
'output string x 3
Public strOut, strOut1, strOut2
Public strAbbrevValue  'value name without type prefix
'output file msg x 2, warning string, title line
Dim strLine, strLine1, strLine2, strWarn, strTitleLine
'register key x 3, sub-key, CLSID key
Dim strKey, strKey1, strKey2, strSubKey, strCLSIDKey
'output file name string (incl. path), file name (wo path),
'PIF path string, single binary character
Dim strFN, strFNNP, strPIFTgt, bin1C
Dim strRptOutput : strRptOutput = "Output limited to non-default values, " &_
 "except where indicated by " & DQ & "{++}" & DQ  'output file string
Public strTitle : strTitle = ""
Public strSubTitle : strSubTitle = ""
Public strSubSubTitle : strSubSubTitle = ""
Dim strDLL, strCN  'DLL name, company name
'string to signal all output by default
Public strAllOutDefault : strAllOutDefault = ""
Dim strCTHL  'CLSID Title Hive Location Prefix (SW\Classes or SW\Wow6432Node\Classes)

Dim ScrPath : ScrPath = Fso.GetParentFolderName(WScript.ScriptFullName)
If Right(ScrPath,1) <> "\" Then ScrPath = ScrPath & BS
'initialize Path of Output File Folder to script path
Dim strPathOFFo : strPathOFFo = ScrPath

'integer variables
'error numbers x 13
Dim intErrNum0, intErrNum1, intErrNum2, intErrNum3, intErrNum4, intErrNum5, intErrNum6, intErrNum7
Dim intErrNum8, intErrNum9, intErrNum10, intErrNum11, intErrNum12, intErrNum13
Public intCLL : intCLL = 0
Dim intBits : intBits = 32  '32- or 64-bit OS
Dim intHKE  'Hive Key Enabler
Dim intLBSP  'Last BackSlash Position in path string
Dim intSS  'lowest sort subscript
Dim intType  'value type
Dim intCTHLS  'CLSID Title Hive Location Spaces
Dim intCS : intCS = 19  'CLSID Spaces
Dim intCWS : intCWS = 25  'CLSID Wow Spaces
Dim intValue, intValue1, intValue2  'values x 3

'flags
Dim flagGP : flagGP = False  'assume Group Policies cannot be set in the OS
Dim flagElevated : flagElevated = False  'existence of elevated privileges in WVa/Wn7
'infection/hijack warning detection flags -- add footer note if True
Public flagIWarn : flagIWarn = False
Public flagHWarn : flagHWarn = False
'TRUE if show all output (default values not filtered)
Public flagShowAll : flagShowAll = False
Dim flagAccess : flagAccess = False
Public flagNames : flagNames = False  'existence of names under a key
Public flagInfect : flagInfect = False  'flag infected condition
Dim flagMatch  'flag matching keys
Dim flagAllow  'flag key on approved list
Dim flagFound  'flag something that exists
Public flagValueFound  'flag value that exists in Registry
Dim flagDirArg : flagDirArg = False  'presence of output directory argument
Dim flagIsCLSID : flagIsCLSID = False  'true if argument in CLSID format
Dim flagTitle  'True if title has already been written
Dim flagAllArg : flagAllArg = False  'presence of all output argument
Dim flagArray  'flag array containing elements
Public flagSupp : flagSupp = False  'do *not* check for DESKTOP.INI in all
                                    'directories of local fixed disks
Public flagWOW : flagWOW = False  'True if in 32-bit environment under 64-bit OS

'times
Public datLaunch : datLaunch = Now  'script launch time
'ref time, time taken by 2 pop-up boxes
Public datRef : datRef = 0
Public datPUB1 : datPUB1 = 0 : Public datPUB2 : datPUB2 = 0

'set up argument usage message string
Dim strLSp, strCSp  'Leading Spaces, Centering Spaces
strLSp = Space(4) : strCSp = Space(33)  'WScript spacing
If flagOut = "C" Then  'CScript spacing
 strLsp = Space(3) : strCSp = Space(28)
End If

'Winver.exe is in \Windows under W98, but in \System32 for other OS's
'trap GetFileVersion error for VBScript version < 5.1
On Error Resume Next
 If Fso.FileExists (strFPSF & "\Winver.exe") Then
  strSysVer = Fso.GetFileVersion(strFPSF & "\Winver.exe")
 Else
  strSysVer = Fso.GetFileVersion(strFPWF & "\Winver.exe")
 End If
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if GetFileVersion returns error due to old WSH version
If intErrNum <> 0 Then

 'store dl URL
 strURL = "http://bit.ly/JIZp7"

 'if using WScript
 If flagOut = "W" Then

  'explain the problem
  intMB = MsgBox ("This script requires Windows Script Host (WSH) 5.1 " &_
   "or higher to run." &_
   vbCRLF & vbCRLF &_
   "If you're running Windows 95, 98, or NT 4.0, WSH is no longer available" &_
   vbCRLF & "from Microsoft." &_
   vbCRLF & vbCRLF &_
   "If you're running Windows XP, press " & DQ & "OK" &_
   DQ & " to direct" & vbCRLF &_
   "your browser to Microsoft to download WSH 5.7 or " & DQ & "Cancel" & DQ & " to quit." &_
   vbCRLF & vbCRLF &_
   "BTW, WMI is also required. If it's missing, download instructions will" & vbCRLF &_
   "appear later.", vbOKCancel + vbExclamation, _
   "Unsupported WSH Version!")

  'if dl wanted now, send browser to dl site
  If intMB = 1 Then Wshso.Run strURL

 'if using CScript
 Else  'flagOut = "C"

  'explain the problem
  WScript.Echo DQ & "Silent Runners" & DQ & " requires " &_
   "Windows Script Host 5.1 or higher to run." & vbCRLF & vbCRLF &_
  "It can be downloaded at: " & strURL

 End If  'WScript or CScript?

 'quit the script
 WScript.Quit

End If  'VBScript version error encountered?

'test for WMI connection; use WMI to find OS & SP#
On Error Resume Next
 'get the OS collection
 Set colOS = GetObject("winmgmts:\root\cimv2").ExecQuery _
  ("Select * from Win32_OperatingSystem")

 intErrNum = Err.Number
On Error GoTo 0

If intErrNum <> 0 Then

 intMB = MsgBox (DQ & "Silent Runners" & DQ & " cannot use WMI to " &_
  "identify the operating system." & vbCRLF & "Either WMI is missing or " &_
  "corrupt." &_
  vbCRLF & vbCRLF &_
  "If you're using Windows 95/98/98 SE, then WMI may not be installed." & vbCRLF &_
  "It can be downloaded here: http://tinyurl.com/jbxe" & vbCRLF & vbCRLF &_
  "If you're using Windows NT 4.0, WMI can be downloaded here:" & vbCRLF &_
  "http://tinyurl.com/7wd7" & vbCRLF & vbCRLF &_
  "If WMI *is* installed, it may be corrupt. WMI is complex and it's" & vbCRLF &_
  "recommended that you use a Microsoft tool, " & DQ & "WMIDiag" & DQ & "," & vbCRLF &_
  "to diagnose WMI on your system. It can be downloaded here:" & vbCRLF &_
  "http://tinyurl.com/4yj9m2q",_
  vbOKOnly + vbCritical + + vbSystemModal + vbDefaultButton2,_
  "Can't connect to WMI Win32_OperatingSystem!")

 WScript.Quit

End If  'WMI connection error?

'find OS name, abbreviation & SP #
'strOS values: W98, NT4, WME, W2K, WXP, WVA, WN7
For Each oOS in colOS

 If InStr(oOS.Name,"|") > 1 Then
  strOSLong = Left(oOS.Name,InStr(oOS.Name,"|")-1)
 Else
  strOSLong = oOS.Name
 End If

 'assign abbreviation
 If InStr(strOSLong,"Windows 95") > 0 Then strOS = "W98"
 If InStr(strOSLong,"Windows 98") > 0 Then
  strOS = "W98"
  'id W98 SE
  If Instr(Wshso.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\VersionNumber"), _
   "2222") > 0 Then strOSLong = "Windows 98 Second Edition"
 End If
 If InStr(strOSLong,"Windows NT") > 0 Then strOS = "NT4"

 'complement WME id
 If InStr(strOSLong,"Windows ME") > 0 Then
  strOS = "WME"
  strOSLong = strOSLong & SP & "(Millennium Edition)"
 End If

 If InStr(strOSLong,"Windows 2000") > 0 Then strOS = "W2K"
 If InStr(strOSLong,"Windows XP") > 0 Then strOS = "WXP"
 If InStr(strOSLong,"2003") > 0 Then
  strOS = "WXP" : strOSSS = "WS2K3"
 End If
 If InStr(strOSLong,"Vista") > 0 Then strOS = "WVA"
 If InStr(strOSLong,"Windows 7") > 0 Or _
  InStr(strOSLong,"Windows" & Chr(160) & "7") > 0 Then strOS = "WN7"
 If InStr(strOSLong,"Windows 8") > 0 Or _
  InStr(strOSLong,"Windows" & Chr(160) & "8") > 0 Then
   strOS = "WN7" : strOSSS = "WN8"
 End If
 If InStr(strOSLong,"Windows 10") > 0 Or _
  InStr(strOSLong,"Windows" & Chr(160) & "10") > 0 Then
   strOS = "WN7" : strOSSS = "W10"
 End If
 If InStr(strOSLong,"Windows Server 2008") > 0 Or _
  InStr(strOSLong,"Windows" & Chr(160) & "Server" & Chr(160) & "2008") > 0 Then _
  strOS = "WN7"

 'id NT version & SP #
 If strOS = "NT4" Then
  'add NT version #
  strOSLong = strOSLong & SP & Wshso.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")
  'add SP #
  strOSLong = strOSLong & SP & Wshso.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion")
 'add SP # for W2K/WXP/WVA/WN7
 ElseIf strOS <> "W98" And strOS <> "WME" then
  'add SP # (RTrim imposed by WVA)
  If oOS.ServicePackMajorVersion >= 1 Then strOSLong = RTrim(strOSLong) &_
   " Service Pack " & oOS.ServicePackMajorVersion
 End If

 'reset HKCU/HKLM CLSID lower limit for OS <= NT4
 If strOS = "W98" Or strOS = "NT4" Or strOS = "WME" Then intCLL = 1

 'reset flagGP for OS's using Group Policy
 If strOS = "W2K" Or strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then _
  flagGP = True

 Exit For

Next  'oOS

Set colOS=Nothing

'quit if OS unknown
If strOS = "Unknown" Then

 If flagOut = "W" Then

  intMB = MsgBox ("The " & DQ & "Silent Runners" & DQ &_
   " script cannot determine the operating system. " &_
   vbCRLF & "A compatible version of the script may be available." &_
   vbCRLF & vbCRLF &_
   "Click " & DQ & "OK" & DQ & " to be directed to the script download location or" &_
   vbCRLF & DQ & "Cancel" & DQ & " to quit.", _
   vbOKCancel + vbExclamation + vbSystemModal,"OS Unknown!")

  If intMB = 1 Then Wshso.Run "http://www.silentrunners.org/"

'  If intMB = 1 Then Wshso.Run "mailto:Andrew%20Aronoff%20" &_
'   "<%6F%73.%76%65%72.%65%72%72%6F%72@%73%69%6C%65%6E%74%72%75%6E%6E%65%72%73.%6F%72%67>?" &_
'   "subject=Silent%20Runners%20OS%20Version%20Error&body=WINVER.EXE" &_
'   "%20file%20version%20=%20" & strSysVer

 Else  'flagOut = "C"

  WScript.Echo DQ & "Silent Runners" & DQ & " cannot " &_
   "determine the operating system." & vbCRLF & vbCRLF & "This script will exit."

 End If  'flagOut?

 WScript.Quit

End If  'stOS Unknown?


'determine if 32-bit or 64-bit, quit if 32-bit under 64-bit
If strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then

 If UCase(Wshso.ExpandEnvironmentStrings("%PROCESSOR_ARCHITEW6432%")) = "AMD64" Then

  MsgBox DQ & "Silent Runners" & DQ & " has been launched as a " &_
   "32-bit process in a 64-bit OS," & vbCRLF &_
   "which will prevent it from functioning correctly." & vbCRLF & vbCRLF &_
   "This script must exit.",vbOKOnly + vbCritical + vbSystemModal, _
   "32-bit process in 64-bit OS!"

  WScript.Quit

 ElseIf UCase(Wshso.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")) = "AMD64" Then

  intBits = 64 :  strOSLong = strOSLong & SP & "(64-bit)"

 Else  '32-bit

  strOSLong = strOSLong & SP & "(32-bit)"

 End If  'env string=amd64?

 'append W10 version number
 If strOSSS = "W10" Then
  strTemp = ""
  On Error Resume Next
   strTemp = Wshso.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ReleaseId")
  On Error Goto 0
  If strTemp = "" Then
   strOSLong = strOSLong & " (version unavailable)"
  Else
   strOSLong = strOSLong & ", Version " & strTemp
  End If  'version MT?

 End If  'env string=amd64?

End If  'WXP/WVA/WN7?


'interpret command-line arguments
strArgUAC = "" : strArgs = ""

If WshoArgs.count > 0 Then

 'copy all arguments, quote-enclose & concatenate
 For i = 0 To (WshoArgs.count-1)
  ReDim Preserve arArgsCopy(i+1)
  arArgsCopy(i) = WshoArgs(i)
  strArgs = LTrim(strArgs & SP & DQ & WshoArgs(i) & DQ)
 Next

 'test 1st arg for elevated privileges string
 If Len(arArgsCopy(0)) >= 7 Then

  If InStr(arArgsCopy(0), "__UAC__") > 0 Then
   strArgUAC = "__UAC__"
   arArgsCopy(0) = Replace (arArgsCopy(0),"__UAC__","",1,1,1)
  End If

 End If  'Len >= 7?

End If  'argument(s) passed to script?

Set oReg = GetObject("winmgmts:root\default:StdRegProv")
strKey = "System\CurrentControlSet\Control\Session Manager"

'if on first pass w/o elevated privileges, launch re-entry
'via Shell.Application with runas

'for WVa/Wn7, relaunch with admin rights unless elevated privileges already provided
If strOS = "WVA" Or strOS = "WN7" Then

 'check for Admin rights
 intErrNum = oReg.CheckAccess(HKLM,strKey,KQV + KSV,flagAccess)

 'if can't read & write to Session Manager and on second pass
 If Not flagAccess And strArgUAC = "__UAC__" Then

  'warn about lack of admin rights and quit
  MsgBox "This script requires admin rights." &_
   vbCRLF & vbCRLF &_
   "This script must exit.",vbOKOnly + vbCritical + vbSystemModal, _
   "Admin rights required!"

  WScript.Quit

 'if can't read & write to Session Manager (and on initial pass)
 ElseIf Not flagAccess Then

  strArgs = "__UAC__" & strArgs

  Set oShellApp = CreateObject("Shell.Application")
  oShellApp.ShellExecute WScript.FullName, _
   DQ & WScript.ScriptFullName & DQ & Space(1) & strArgs, "", "runas", 1

  WScript.Quit

 End If  'flagAccess?

End If  'WVA Or WN7?

strOut = "Only two arguments are permitted:" &_
 vbCRLF & vbCRLF &_
 "1. the name of an existing directory for the output report" &_
 vbCRLF & strLSp & "(embed in quotes if it contains spaces)" &_
 vbCRLF & vbCRLF & strCSp & "AND:" & vbCRLF & vbCRLF &_
 "2. " & DQ & "-supp" & DQ & " to search " &_
 "all directories for DESKTOP.INI DLL" & vbCRLF &_
 strLSp & "launch points" &_
 vbCRLF & vbCRLF & strCSp & "-OR-" & vbCRLF & vbCRLF &_
 "3. " & DQ & "-all" & DQ & " to output all non-empty " &_
 "values and all launch" & vbCRLF & strLSp & "points checked"

'check if output directory or "-all" or "-supp" was supplied as argument
If WshoArgs.count > 0 And WshoArgs.count <= 2 Then

 For i = 0 To WshoArgs.count-1

  'if directory arg not already passed and arg directory exists
  If Not flagDirArg And Fso.FolderExists(arArgsCopy(i)) Then

   'get the path & toggle the directory arg flag
   Set oOFFo = Fso.GetFolder(arArgsCopy(i))
   strPathOFFo = oOFFo.Path : flagDirArg = True
   If Right(strPathOFFo,1) <> "\" Then strPathOFFo = strPathOFFo & BS
   Set oOFFo=Nothing

  'if -all arg not already passed and is this arg
  ElseIf Not flagAllArg And LCase(arArgsCopy(i)) = "-all" Then

   'toggle ShowAll flag, toggle the all arg flag, fill report string
   flagShowAll = True : flagAllArg = True
   strRptOutput = "Output of all locations checked and all values found."

  'if -all arg not already passed and this arg is -supp
  ElseIf Not flagAllArg And LCase(arArgsCopy(i)) = "-supp" Then
   flagSupp = True : flagAllArg = True
   strRptOutput = "Search enabled of all directories on local fixed " &_
    "drives for DESKTOP.INI DLL launch points" &_
    vbCRLF & strRptOutput

  'non-empty argument can't be interpreted, so explain & quit
  ElseIf arArgsCopy(i) <> "" Then

   If flagOut = "W" Then  'pop up a message window

    MsgBox "The argument:" & vbCRLF &_
     DQ & UCase(arArgsCopy(i)) & DQ & vbCRLF &_
    "... can't be interpreted." & vbCRLF & vbCRLF &_
     strOut, vbOKOnly + vbExclamation,"Bad Script Argument"

   Else  'flagOut = "C"  'write the message to the console

    WScript.Echo vbCRLF & "The argument: " &_
     DQ & UCase(arArgsCopy(i)) & DQ &_
     " can't be interpreted." & vbCRLF & vbCRLF &_
     strOut & vbCRLF

   End If  'WScript host?

   WScript.Quit

  End If  'argument can be interpreted?

 Next  'argument

'too many args passed
ElseIf WshoArgs.count > 2 Then

 'explain & quit
 If flagOut = "W" Then  'pop up a message window

  Wshso.Popup "Too many arguments (" & WshoArgs.count & ") were passed." &_
   vbCRLF & vbCRLF & strOut,10,"Too Many Arguments",_
   vbOKOnly + vbCritical

 Else  'flagOut = "C"  'write the message to the console

  WScript.Echo "Too many arguments (" & WshoArgs.count & ") were passed." &_
   vbCRLF & vbCRLF & strOut & vbCRLF

 End If  'WScript host?

 WScript.Quit

End If  'directory arguments passed?

Set WshoArgs=Nothing

datRef = Now

'if no cmd line argument for flagSupp and not testing, show popup
If Not flagTest And Not flagShowAll And Not flagSupp And flagOut = "W" Then

 intMB = Wshso.Popup ("Do you want to skip the supplementary search?" &_
  vbCRLF & "(It typically takes several minutes.)" & vbCRLF & vbCRLF &_
  "Press " & DQ & "Yes" & DQ & Space(5) &_
  " to skip the supplementary search (default)" & vbCRLF & vbCRLF &_
  Space(10) & DQ & "No" & DQ & Space(6) &_
  " to perform it, or" & vbCRLF & vbCRLF &_
  Space(10) & DQ & "Cancel" & DQ &_
  " to get more information at the web site" & vbCRLF &_
  Space(25) & "and exit the script.",_
  15,"Skip supplementary search?",_
  vbYesNoCancel + vbQuestion + vbDefaultButton1 + vbSystemModal)

 If intMB = vbNo Then

  flagSupp = True

  intMB1 = MsgBox ("Are you SURE you want to run the supplementary " &_
   "search?" & vbCRLF & vbCRLF & "It's _rarely_ necessary " &_
   "and it takes a *long* time." & vbCRLF & vbCRLF & "Press " & DQ &_
   "Yes" & DQ & " to confirm running the supplementary search, " &_
   "or" & vbCRLF & Space(10) & DQ & "No" & DQ & " to run without it.", _
   vbYesNo + vbQuestion + vbDefaultButton2 + vbSystemModal,"Are you sure?")

   If intMB1 = vbNo Then flagSupp = False

 ElseIf intMB = vbCancel Then
  Wshso.Run "http://www.silentrunners.org/sr_thescript.html#supp"
  WScript.Quit
 End If

End If

datPUB1 = DateDiff("s",datRef,Now) : datRef = Now

'inform user that script has started
If Not flagTest Then
 If flagOut = "W" Then
  Wshso.PopUp DQ & "Silent Runners" & DQ & " has started." &_
   vbCRLF & vbCRLF & "A message box like this one will appear " &_
   "when it's done." & vbCRLF & vbCRLF & "Please be patient...",3,_
   "Silent Runners R" & strRevNo & " startup", _
   vbOKOnly + vbInformation + vbSystemModal
 Else
  WScript.Echo DQ & "Silent Runners" & DQ & " has started." &_
   " Please be patient..." & vbCRLF
 End If  'flagOut?
End If  'flagTest?

datPUB2 = DateDiff("s",datRef,Now)

'create Unicode output file name with computer name & today's date
'Startup Programs (pc_name_here) yyyy-mm-dd.txt

strFNNP = "Startup Programs (" & oNetwk.ComputerName & ") " &_
 FmtDate(datLaunch) & " " & FmtHMS(datLaunch) & ".txt"
strFN = strPathOFFo & strflagTest & strFNNP
On Error Resume Next
 If Fso.FileExists(strFN) Then Fso.DeleteFile(strFN)
 Err.Clear
 Public oFN : Set oFN = Fso.CreateTextFile(strFN,True,True)
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if can't create report file
If intErrNum > 0 Then

  strURL = "http://www.silentrunners.org/Silent%20Runners%20RED.vbs"

 'invite user to run RED version & quit
 If flagOut = "W" Then

  intMB = MsgBox ("The script cannot create its report file. " &_
   "This is a known, intermittent" & vbCRLF & "problem under " &_
   strOSLong & "." & vbCRLF & vbCRLF &_
   "An alternative script version is available for download. " &_
   "After it runs, " & vbCRLF & "the script you're using now will " &_
   "run correctly." & vbCRLF & vbCRLF &_
   "Press " & DQ & "OK" & DQ & " to direct your browser " &_
   "to the alternate script location, or" & vbCRLF & Space(10) &_
   DQ & "Cancel" & DQ & " to quit.",49,"CreateTextFile Error!")

  'if alternative script wanted now, send browser to dl site
  If intMB = 1 Then Wshso.Run strURL

 'explain & quit
 Else  'flagOut = "C"

  WScript.Echo DQ & "Silent Runners" & DQ & " cannot " &_
   "create the report file." & vbCRLF & vbCRLF &_
   "An alternative script is available. Run it, then rerun this version." &_
   vbCRLF & "The alternative script can be downloaded at: " & vbCRLF &_
   vbCRLF & strURL

 End If

 WScript.Quit

End If  'report file creation error?

Set oNetwk=Nothing

'add report header
oFN.WriteLine DQ & "Silent Runners.vbs" & DQ &_
 ", revision " & strRevNo & ", http://www.silentrunners.org/" &_
 vbCRLF & "Operating System: " & strOSLong & vbCRLF & strRptOutput




'#1. HKCU/HKLM/HKLM-WOW... Run
'    HKCU/HKLM... RunOnce/RunOnce\Setup/RunOnceEx
'    HKLM... RunServices/RunServicesOnce
'    HKCU/HKLM/HKLM-WOW... Policies\Explorer\Run

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'write registry header lines to file
strTitle = "Startup items buried in registry:"
TitleLineWrite


'put keys in array (Key Index 0 - 9)
arRunKeys = Array ("Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", _
 "Software\Microsoft\Windows\CurrentVersion\Run", _
 "Software\Microsoft\Windows\CurrentVersion\RunOnce", _
 "Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup", _
 "Software\Microsoft\Windows\CurrentVersion\RunOnceEx", _
 "Software\Microsoft\Windows\CurrentVersion\RunServices", _
 "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", _
 "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", _
 "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", _
 "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")

'0 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
'1 Software\Microsoft\Windows\CurrentVersion\Run
'2 Software\Microsoft\Windows\CurrentVersion\RunOnce
'3 Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup
'4 Software\Microsoft\Windows\CurrentVersion\RunOnceEx
'5 Software\Microsoft\Windows\CurrentVersion\RunServices
'6 Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
'7 Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
'8 Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
'9 Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx

'RunOnceEx: values at this key are informational (they are *not* executed)
' but are displayed by the script. (The value for the "Title" name is used
' by Windows.)
'
' HKCU\RunOnceEx launches *only* if HKLM\RunOnceEx is populated and it
' launches _after_ the HKLM executable has exited
' HKCU\Wow6432Node\RunOnceEx does not launch under any circumstances

'Policies\Explorer\Run: HKLM...Wow6432Node is mirror of HKLM and
'modification/deletion of one modifies/deletes the other


'Key Execution Flag/Subkey Recursion Flag array

'first number in the ordered pair in the array immediately below
' pertains to execution of the key:
'0: not executed (ignore)
'1: may be executed so display with EXECUTION UNLIKELY warning
'2: executable

'second number in the ordered pair pertains to subkey recursion
'0: subkeys not used
'1: subkey recursion necessary

'Hive                   HKCU - 0                                  HKLM - 1
'
'Key      0   1   2   3   4   5   6   7   8   9     0   1   2   3   4   5   6   7   8   9
'Index

'OS:
'W95     0,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   0,0 2,0 2,0 0,0 2,1 2,0 2,0 0,0 0,0 0,0
'W98     0,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   0,0 2,0 2,0 2,0 2,1 2,0 2,0 0,0 0,0 0,0
'WMe     2,1 2,1 2,0 2,0 2,1 0,0 0,0 0,0 0,0 0,0   2,1 2,1 2,0 2,0 2,1 2,0 2,0 0,0 0,0 0,0
'NT4     0,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   0,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'W2K     2,1 2,1 2,1 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,1 2,1 2,1 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'WXP     2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'WXP64   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 2,0 2,0 2,1
'WS2K3   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'WS2K364 2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 2,0 2,0 2,1
'WVa     2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'WVa64   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 2,0 2,0 2,1
'Wn7     2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0
'Wn764   2,0 2,0 2,0 0,0 2,1 0,0 0,0 0,0 0,0 0,0   2,0 2,0 2,0 0,0 2,1 0,0 0,0 2,0 2,0 2,1

'arRegFlag(i,j,k): put flags in array by OS:
'hive = i (0 or 1), key_# = j (0-9),
'flags (key execution/subkey recursion) = k (0 or 1)
' k = 0 holds key execution value = 0/1/2
'     1 holds subkey recursion value = 0/1
Dim arRegFlag(1,9,1)

'initialize entire array to zero
For i = 0 To 1 : For j = 0 To 9 : For k = 0 To 1
 arRegFlag(i,j,k) = 0
Next : Next : Next

'add data to array for OS that's running

'W98
If strOS = "W98" Then
 arRegFlag(0,1,0) = 2  'HKCU,Run = no-warn
 arRegFlag(0,2,0) = 2  'HKCU,RunOnce = no-warn
 arRegFlag(0,4,0) = 2  'HKCU,RunOnceEx = no-warn
 arRegFlag(0,4,1) = 1  'HKCU,RunOnceEx = sub-keys
 arRegFlag(1,1,0) = 2  'HKLM,Run = no-warn
 arRegFlag(1,2,0) = 2  'HKLM,RunOnce = no-warn

 'don't set HKLM,RunOnce\Setup for W95
 If InStr(strOSLong,"Windows 98") > 0 Then arRegFlag(1,3,0) = 2  'HKLM,RunOnce\Setup = no-warn

 arRegFlag(1,4,0) = 2  'HKLM,RunOnceEx = no-warn
 arRegFlag(1,4,1) = 1  'HKLM,RunOnceEx = sub-keys
 arRegFlag(1,5,0) = 2  'HKLM,RunServices = no-warn
 arRegFlag(1,6,0) = 2  'HKLM,RunServicesOnce = no-warn
End If

If strOS = "WME" Then
 arRegFlag(0,0,0) = 2  'HKCU,Policies\Explorer\Run = no-warn
 arRegFlag(0,0,1) = 1  'HKCU,Policies\Explorer\Run = sub-keys
 arRegFlag(0,1,0) = 2  'HKCU,Run = no-warn
 arRegFlag(0,1,1) = 1  'HKCU,Run = sub-keys
 arRegFlag(0,2,0) = 2  'HKCU,RunOnce = no-warn
 arRegFlag(0,3,0) = 2  'HKCU,RunOnce\Setup = no-warn
 arRegFlag(0,4,0) = 2  'HKCU,RunOnceEx = no-warn
 arRegFlag(0,4,1) = 1  'HKCU,RunOnceEx = sub-keys
 arRegFlag(1,0,0) = 2  'HKLM,Explorer\Run = no-warn
 arRegFlag(1,0,1) = 1  'HKLM,Explorer\Run = sub-keys
 arRegFlag(1,1,0) = 2  'HKLM,Run = no-warn
 arRegFlag(1,1,1) = 1  'HKLM,Run = sub-keys
 arRegFlag(1,2,0) = 2  'HKLM,RunOnce = no-warn
 arRegFlag(1,3,0) = 2  'HKLM,RunOnce\Setup = no-warn
 arRegFlag(1,4,0) = 2  'HKLM,RunOnceEx = no-warn
 arRegFlag(1,4,1) = 1  'HKLM,RunOnceEx = sub-keys
 arRegFlag(1,5,0) = 2  'HKLM,RunServices = no-warn
 arRegFlag(1,6,0) = 2  'HKLM,RunServicesOnce = no-warn
End If

'NT4
If strOS = "NT4" Then
 arRegFlag(0,1,0) = 2  'HKCU,Run = no-warn
 arRegFlag(0,2,0) = 2  'HKCU,RunOnce = no-warn
 arRegFlag(0,4,0) = 2  'HKCU,RunOnceEx = no-warn
 arRegFlag(0,4,1) = 1  'HKCU,RunOnceEx = sub-keys
 arRegFlag(1,1,0) = 2  'HKLM,Run = no-warn
 arRegFlag(1,2,0) = 2  'HKLM,RunOnce = no-warn
 arRegFlag(1,4,0) = 2  'HKLM,RunOnceEx = no-warn
 arRegFlag(1,4,1) = 1  'HKLM,RunOnceEx = sub-keys
End If

'W2K
If strOs = "W2K" Then
 arRegFlag(0,0,0) = 2  'HKCU,Policies\Explorer\Run = no-warn
 arRegFlag(0,0,1) = 1  'HKCU,Policies\Explorer\Run = sub-keys
 arRegFlag(0,1,0) = 2  'HKCU,Run = no-warn
 arRegFlag(0,1,1) = 1  'HKCU,Run = sub-keys
 arRegFlag(0,2,0) = 2  'HKCU,RunOnce = no-warn
 arRegFlag(0,2,1) = 1  'HKCU,RunOnce = sub-keys (incl. Setup)
 arRegFlag(0,4,0) = 2  'HKCU,RunOnceEx = no-warn
 arRegFlag(0,4,1) = 1  'HKCU,RunOnceEx = sub-keys
 arRegFlag(1,0,0) = 2  'HKLM,Explorer\Run = no-warn
 arRegFlag(1,0,1) = 1  'HKLM,Explorer\Run = sub-keys
 arRegFlag(1,1,0) = 2  'HKLM,Run = no-warn
 arRegFlag(1,1,1) = 1  'HKLM,Run = sub-keys
 arRegFlag(1,2,0) = 2  'HKLM,RunOnce = no-warn
 arRegFlag(1,2,1) = 1  'HKLM,RunOnce = sub-keys (incl. Setup)
 arRegFlag(1,4,0) = 2  'HKLM,RunOnceEx = no-warn
 arRegFlag(1,4,1) = 1  'HKLM,RunOnceEx = sub-keys
End If

'WXP/WVa/Wn7
If strOs = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then
 arRegFlag(0,0,0) = 2  'HKCU,Policies\Explorer\Run = no-warn
 arRegFlag(0,1,0) = 2  'HKCU,Run = no-warn
 arRegFlag(0,2,0) = 2  'HKCU,RunOnce = no-warn
 arRegFlag(0,4,0) = 2  'HKCU,RunOnceEx = no-warn
 arRegFlag(0,4,1) = 1  'HKCU,RunOnceEx = sub-keys
 arRegFlag(1,0,0) = 2  'HKLM,Explorer\Run = no-warn
 arRegFlag(1,1,0) = 2  'HKLM,Run = no-warn
 arRegFlag(1,2,0) = 2  'HKLM,RunOnce = no-warn
 arRegFlag(1,4,0) = 2  'HKLM,RunOnceEx = no-warn
 arRegFlag(1,4,1) = 1  'HKLM,RunOnceEx = sub-keys

 'for 64-bit OS, enable HKLM|Wow6432Mode,Policies\Explorer\Run
 '                      HKLM|Wow6432Node...Run
 '                      HKLM|Wow6432Node...RunOnceEx
 If intBits = 64 Then
  arRegFlag(1,7,0) = 2  'HKLM|Wow6432Mode,Policies\Explorer\Run = no-warn
  arRegFlag(1,8,0) = 2  'HKLM|Wow6432Mode,Run = no-warn
  arRegFlag(1,9,0) = 2  'HKLM|Wow6432Mode,RunOnceEx = no-warn
  arRegFlag(1,9,1) = 1  'HKLM|Wow6432Mode,RunOnceEx = sub-keys
 End If  'x64?

End If  'WXP/WVA/WN7?

'if not ShowAll, show all output for Run keys
If Not flagShowAll Then strAllOutDefault = " {++}"

'for each hive
For i = 0 To 1

 'for each key
 For j = 0 To 9

  'if key is not ignored
  If arRegFlag(i,j,0) > 0 Then

   flagNames = False

   'intialize string with warning if necessary
   strWarn = ""
   If arRegFlag(i,j,0) = 1 Then strWarn = "EXECUTION UNLIKELY: "

   'INFO
   'with no name/value pairs (sub-keys are identical)
   'array must not be Dimmed as dynamic()
   '
   '      IsArray    TypeName    UBound
   'W98    True     "Variant()"    -1
   'WMe    True     "Variant()"    -1
   'NT4    True     "Variant()"    -1
   'W2K    False      "Null"      error (--)
   'WXP    False      "Null"      error (--)
   'WS2K3  False      "Null"      error (--)
   'WVa    False      "Null"      error (--)
   'Wn7    False      "Null"      error (--)

   'enumerate names and types under a key
   EnumNT arHives(i,1), arRunKeys(j), arNames, arType

   If flagNames Then  'name/value pairs exist

    'write the full key name
    oFN.WriteLine vbCRLF & SOCA(arHives(i,0) & BS & arRunKeys(j) &_
     BS & strAllOutDefault)

     'for each data type in the names array
    For k = LBound(arNames) To UBound(arNames)

     'use the type to find the value
     strValue = RtnValue (arHives(i,1), arRunKeys(j), arNames(k), arType(k))
     'write the name & value
     WriteValueData arNames(k), strValue, arType(k), strWarn

    Next  'member of names array

   Else  'no name/value pairs

    If flagShowAll Then _
     oFN.WriteLine vbCRLF & SOCA(arHives(i,0) & BS & arRunKeys(j) & BS)

   End If  'flagNames?

   'recurse subkeys if necessary
   If arRegFlag(i,j,1) = 1 Then

    'put all subkeys into array
    oReg.EnumKey arHives(i,1),arRunKeys(j),arKeys

    'excludes W2K/WXP/WVa/Wn7 with no sub-keys
    If IsArray(arKeys) Then

     'excludes W98/WMe/NT4 with no sub-keys
     For Each strMemKey in arKeys

      flagNames = False
      strSubKey = arRunKeys(j) & BS & strMemKey

      EnumNT arHives(i,1), arRunKeys(j) & BS & strMemKey,arNames,arType

      If flagNames Then  'if name/value pairs exist

       'write the full key name
       oFN.WriteLine vbCRLF & SOCA(arHives(i,0) & BS & strSubKey &_
        BS & strAllOutDefault)

       'for each data type in the names array
       For k = LBound(arNames) To UBound(arNames)

        'use the type to find the value
        strValue = RtnValue (arHives(i,1), strSubKey, arNames(k), arType(k))
        'write the name & value
        WriteValueData arNames(k), strValue, arType(k), strWarn

       Next  'member of names array

      Else  'no name/value pairs

       If flagShowAll Then _
        oFN.WriteLine vbCRLF & SOCA(arHives(i,0) & BS & strSubKey & BS)

      End If  'flagNames?

     Next  'sub-key

    End If  'sub-keys exist? W2K/WXP/WVa/Wn7

   End If  'enum sub-keys?

  End If  'arRegFlag(i,j,0) > 0

 Next  'Run key

Next  'Hive

strAllOutDefault = "" : flagNames = False

End If  'flagTest And SecTest?




'#2. HKLM/HKLM-WOW... Active Setup\Installed Components\
'    HKCU/HKCU-WOW... Active Setup\Installed Components\

'if HKLM key exists with StubPath value (SPV), SPV will execute on
'next logon, creating HKCU key with same name
'HKLM key name can be any alphanumeric, GUIDs included
'if HKLM Version value exists, it will be placed into HKCU key
'if HKLM Version value does not exist (or has bad format), HKCU key will be empty

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'flag True if only numeric & comma chrs in Version value
Dim flagHKLMVer
'StubPath Value, HKLM/HKCU Version, HKLM program name, HKLM array/element
Dim strSPV, strHKLMVer, strHKCUVer, strPgmName, arHKLMKeys, strHKLMKey

arKeys = Array("Software\Microsoft\Active Setup\Installed Components")

'WXP 64-bit ignores HKLM...Wow even though it's populated
If intBits = 64 And strOS <> "WXP" Then

 arKeys = Array("Software\Microsoft\Active Setup\Installed Components", _
  "Software\Wow6432Node\Microsoft\Active Setup\Installed Components")

End If

'for each arKey
For intKey = 0 To UBound(arKeys)

 strSubTitle = SOCA("HKLM" & BS & arKeys(intKey) & BS)

 'find all the subkeys
 oReg.EnumKey HKLM, arKeys(intKey), arHKLMKeys

 'enumerate HKLM keys if present
 If IsArray(arHKLMKeys) Then

  'for each HKLM key
  For Each strHKLMKey In arHKLMKeys

  'INFO
  'Default Value not set:
  'W98/WMe:                   returns 0,        strValue = ""
  'NT4/W2K/WXP/WS2K3/WVa/Wn7: returns non-zero, strValue = Null

  'Non-Default name inexistent:
  'W98/WMe/NT4/W2K/WXP/WS2K3/WVa/Wn7: returns non-zero, strValue = Null

  'Non-Default Value not set:
  'W2K:                           returns 0, strValue = unwritable string
  'W98/WMe/NT4/WXP/WS2K3/WVa/Wn7: returns 0, strValue = ""

   'get the StubPath value
   On Error Resume Next
    intErrNum = oReg.GetStringValue (HKLM,arKeys(intKey) & BS & strHKLMKey,"StubPath",strSPV)
   On Error GoTo 0

   'retrieve the HKLM Version value
   On Error Resume Next
    intErrNum1 = oReg.GetStringValue (HKLM,arKeys(intKey) & BS & strHKLMKey,"Version",strHKLMVer)
   On Error GoTo 0

   'retrieve the program name
   On Error Resume Next
    intErrNum2 = oReg.GetStringValue (HKLM,arKeys(intKey) & BS & strHKLMKey,"",strPgmName)
   On Error GoTo 0

   'if the StubPath name exists And value set (exc for W2K!)
   If intErrNum = 0 And strSPV <> "" Then

    flagMatch = False  'assume StubPath will execute

    'look for HKCU key
    intErrNum3 = oReg.EnumValues (HKCU,arKeys(intKey) & BS & strHKLMKey,arNames,arType)

    'if HKCU key exists
    If intErrNum3 = 0 Then

     flagMatch = True  'assume StubPath will *not* execute

     'if HKLM Version exists
     If intErrNum1 = 0 And strHKLMVer <> "" Then

      'assume correct format (# & ",")
      flagHKLMVer = True

      'toggle flag if one chr found in incorrect format
      For i = 1 To Len(Trim(strHKLMVer))
       strChr = Mid(strHKLMVer,i,1)
       If Not IsNumeric(strChr) And strChr <> "," Then
        flagHKLMVer = False : Exit For
       End If
      Next

      'if HKLM Version format OK, check for HKCU Version and compare
      If flagHKLMVer Then

       'look for HKCU Version value
       On Error Resume Next
        intErrNum3 = oReg.GetStringValue (HKCU,arKeys(intKey) & BS & strHKLMKey,"Version",strHKCUVer)
       On Error GoTo 0

       'toggle flag if HKLM Version > HKCU Version
       'comparison works with comma delimited numeric string
       If Trim(strHKLMver) > Trim(strHKCUVer) Then flagMatch = False

      End If  'flagHKLMVer?

     End If  'HKLM Version value exists?

    End If  'HKCU Installed Components subkey exists?

    'if the StubPath will launch
    If Not flagMatch Then

     flagAllow = False  'assume StubPath DLL not on approved list
     strCN = CoName(IDExe(strSPV))

     'test for lone approved StubPath DLL
     'removed strCN = MS requirement due to W10 StubPath with invalid path
     If LCase(strHKLMKey) = ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95}" And _
      (InStr(LCase(strSPV),"wmpocm.exe") > 0 Or _
      InStr(LCase(strSPV),"unregmp2.exe") > 0) And _
      Not flagShowAll Then flagAllow = True

     'StubPath DLL not approved
     If Not flagAllow Then

      TitleLineWrite

      'output the CLSID & pgm name
      oFN.WriteLine vbCRLF & strHKLMKey & "\(Default) = " & strPgmName

      'output the StubPath value
      oFN.WriteLine Space(Len(strHKLMKey)) & "\StubPath  = " & strSPV & strCN

     End If  'flagAllow false?

    End If  'flagMatch false?

   End If  'StubPath value exists?

  Next  'HKLM Installed Components subkey

 End If  'HKLM Installed Components subkeys exist?

Next  'arKeys member

If flagShowAll Then TitleLineWrite

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#3. HKLM/HKLM-WOW... Explorer\Browser Helper Objects\

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects")

If intBits = 64 Then

 arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", _
  "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects")

End If

For intKey = 0 To UBound(arKeys)

 strSubTitle = SOCA("HKLM" & BS & arKeys(intKey) & BS)

 'find all the subkeys
 oReg.EnumKey HKLM, arKeys(intKey), arSubKeys

 'enumerate data if present
 If IsArray(arSubKeys) Then

  TitleLineWrite

  'for each key
  For Each strSubKey In arSubKeys

   strOut = ""
   CLSID_ID strSubKey, False

   If strOut <> "" Then
    CLSIDLocTitle HKLM, arKeys(intKey) & BS & strSubKey, "", strLocTitle
    oFN.WriteLine vbCRLF & strSubKey & "\(Default) = " & strLocTitle
    oFN.WriteLine strOut
   End If

  Next  'BHO subkey

 Else

  'if ShowAll, output the key name if not already done
  If flagShowAll Then TitleLineWrite

 End If  'BHO subkeys exist?

Next  'arKeys member

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#4. HKCU/HKLM/HKLM-WOW... Explorer\ShellIconOverlayIdentifiers

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

ReDim arAllowedCLSID(14,1)

'Offline Files
arAllowedCLSID(0,0)  = "{750fdf0e-2a26-11d1-a3ea-080036587f03}" : arAllowedCLSID(0,1)  = "cscui.dll"
arAllowedCLSID(1,0)  = "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}" : arAllowedCLSID(1,1)  = "EhStorShell.dll"  'Enhanced Storage Icon Overlay Handler Class
arAllowedCLSID(2,0)  = "{4E77131D-3629-431c-9818-C5679DC83E81}" : arAllowedCLSID(2,1)  = "cscui.dll"
arAllowedCLSID(3,0)  = "{08244EE6-92F0-47f2-9FC9-929BAA2E7235}" : arAllowedCLSID(3,1)  = "ntshrui.dll"
arAllowedCLSID(4,0)  = "{7D688A77-C613-11D0-999B-00C04FD655E1}" : arAllowedCLSID(4,1)  = "shell32.dll"
arAllowedCLSID(5,0)  = "{BBACC218-34EA-4666-9D7A-C78F2274A524}" : arAllowedCLSID(5,1)  = "FileSyncShell64.dll"
arAllowedCLSID(6,0)  = "{5AB7172C-9C11-405C-8DD5-AF20F3606282}" : arAllowedCLSID(6,1)  = "FileSyncShell64.dll"
arAllowedCLSID(7,0)  = "{A78ED123-AB77-406B-9962-2A5D9D2F7F30}" : arAllowedCLSID(7,1)  = "FileSyncShell64.dll"
arAllowedCLSID(8,0)  = "{F241C880-6982-4CE5-8CF7-7085BA96DA5A}" : arAllowedCLSID(8,1)  = "FileSyncShell64.dll"
arAllowedCLSID(9,0)  = "{A0396A93-DC06-4AEF-BEE9-95FFCCAEF20E}" : arAllowedCLSID(9,1)  = "FileSyncShell64.dll"
arAllowedCLSID(10,0) = "{BBACC218-34EA-4666-9D7A-C78F2274A524}" : arAllowedCLSID(10,1) = "FileSyncShell.dll"
arAllowedCLSID(11,0) = "{5AB7172C-9C11-405C-8DD5-AF20F3606282}" : arAllowedCLSID(11,1) = "FileSyncShell.dll"
arAllowedCLSID(12,0) = "{A78ED123-AB77-406B-9962-2A5D9D2F7F30}" : arAllowedCLSID(12,1) = "FileSyncShell.dll"
arAllowedCLSID(13,0) = "{F241C880-6982-4CE5-8CF7-7085BA96DA5A}" : arAllowedCLSID(13,1) = "FileSyncShell.dll"
arAllowedCLSID(14,0) = "{A0396A93-DC06-4AEF-BEE9-95FFCCAEF20E}" : arAllowedCLSID(14,1) = "FileSyncShell.dll"

Dim strCLSIDLoc  'CLSID location (key name or default value)

arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers" )
intHKE = 3  'HKCU...SW + HKLM...SW = 1 + 2

If intBits = 64 Then

 arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", _
  "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers")

 intHKE = 11  'HKCU...SW + HKLM...SW + HKLM...SW\Wow = 1 + 2 + 8
              'omit HKCU...SW\Wow

End If

'for every arKey member
For intKey = 0 To UBound(arKeys)

 'for each hive
 For i = intCLL To 1

  'respect Hive Key Enabler map
  If HKInclude(intHKE,i,intKey) Then

   'assign title
   strSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

   'find all the subkeys
   oReg.EnumKey arHives(i,1), arKeys(intKey), arSubKeys

   'enumerate data if present
   If IsArray(arSubKeys) Then

    'for each subkey
    For Each strSubKey In arSubKeys

    'find default value
     On Error Resume Next
      intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) & BS & strSubKey,"",strCLSID)
     On Error GoTo 0

     'if default value is CLSID
     If intErrNum = 0 And IsCLSID(strCLSID) Then

      'find the default value name
      CLSIDLocTitle arHives(i,1), arKeys(intKey) & BS & strSubKey,"",strLocTitle

      'look for IPSDLL in each hive
      For j = intCLL To 1

       flagMatch = False

       'find CLSID title & IPSDLL
       flagWOW = False
       If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True
       ResolveCLSID strCLSID, arHives(j,1), strCLSIDTitle, strIPSDLL, flagWOW

       'if IPSDLL not empty
       If strIPSDLL <> "" Then

        strCN = CoName(IDExe(strIPSDLL))

        'see if allowed
        For k = 0 To UBound(arAllowedCLSID,1)

         'toggle match flag if allowed CLSID, allowed IPSDLL, CoName = MS
         If Not flagShowAll And LCase(strCLSID) = LCase(arAllowedCLSID(k,0)) And _
          Fso.GetFileName(LCase(strIPSDLL)) = LCase(arAllowedCLSID(k,1)) And _
          strCN = MS Then
           flagMatch = True : Exit For
         End If

        Next  'arAllowedCLSID

        If flagShowAll Or Not flagMatch Then

         'output the title line if not already done
         TitleLineWrite

         oFN.WriteLine vbCRLF & strSubKey & "\(Default) = " & strLocTitle

         strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
         If flagWOW Then
          strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
         End IF

         'output CLSID title, InProcServer32 DLL & CoName
         oFN.WriteLine "  -> {" & arHives(j,0) & strCTHL &_
          strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
          strIPSDLL & strCN

        End If  'flagShowAll or not flagMatch?

       End If  'strIPSDLL exists?

      Next  'CLSID hive

     End If  'default value is CLSID?

    Next  'SIOI subkey

    If flagShowAll Then TitleLineWrite  'W98/WMe/NT4 IFF arKeys(intKey) exists

   Else  'no SIOI subkey array for this hive

    If flagShowAll Then TitleLineWrite

   End If  'SIOI subkeys exist?

  End If  'HKInclude

 Next  'hive

Next  'arKeys member

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arAllowedCLSID(0,0)

End If  'SecTest?




'#5. HKCU/HKLM/HKLM-WOW... Explorer\ShellServiceObjects

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

ReDim arAllowedCLSID(29,1)

'WVA
arAllowedCLSID(0,0) = "{E6FB5E20-DE35-11CF-9C87-00AA005127ED}" : arAllowedCLSID(0,1) = "webcheck.dll"
arAllowedCLSID(1,0) = "{FD6905CE-952F-41F1-9A6F-135D9C6622CC}" : arAllowedCLSID(1,1) = "wscntfy.dll"

'WN7
arAllowedCLSID(2,0)  = "{003e0278-eca8-4bb8-a256-3689ca1c2600}" : arAllowedCLSID(2,1)  = "shell32.dll"
arAllowedCLSID(3,0)  = "{3BF043EF-A974-49B3-8322-B853CF1E5EC5}" : arAllowedCLSID(3,1)  = "SndVolSSO.dll"
arAllowedCLSID(4,0)  = "{566296fe-e0e8-475f-ba9c-a31ad31620b1}" : arAllowedCLSID(4,1)  = "dxp.dll"
arAllowedCLSID(5,0)  = "{68ddbb56-9d1d-4fd9-89c5-c0da2a625392}" : arAllowedCLSID(5,1)  = "stobject.dll"
arAllowedCLSID(6,0)  = "{6FDEDD65-AC51-43CA-B2D0-9EB5D1155D03}" : arAllowedCLSID(6,1)  = "ehSSO.dll"
arAllowedCLSID(7,0)  = "{7007ACCF-3202-11D1-AAD2-00805FC1270E}" : arAllowedCLSID(7,1)  = "netshell.dll"
arAllowedCLSID(8,0)  = "{7849596a-48ea-486e-8937-a2a3009f31a9}" : arAllowedCLSID(8,1)  = "shell32.dll"
arAllowedCLSID(9,0)  = "{900c0763-5cad-4a34-bc1f-40cd513679d5}" : arAllowedCLSID(9,1)  = "hcproviders.dll"
arAllowedCLSID(10,0) = "{A1607060-5D4C-467a-B711-2B59A6F25957}" : arAllowedCLSID(10,1) = "AltTab.dll"
arAllowedCLSID(11,0) = "{AAA288BA-9A4C-45B0-95D7-94D524869DB5}" : arAllowedCLSID(11,1) = "wpdshserviceobj.dll"
arAllowedCLSID(12,0) = "{C2796011-81BA-4148-8FCA-C6643245113F}" : arAllowedCLSID(12,1) = "pnidui.dll"
arAllowedCLSID(13,0) = "{C51F0A6B-2A63-4cf4-8938-24404EAEF422}" : arAllowedCLSID(13,1) = "cscui.dll"
arAllowedCLSID(14,0) = "{DA67B8AD-E81B-4c70-9B91-B417B5E33527}" : arAllowedCLSID(14,1) = "srchadmin.dll"
arAllowedCLSID(15,0) = "{EF4D1E1A-1C87-4AA8-8934-E68E4367468D}" : arAllowedCLSID(15,1) = "shdocvw.dll"
arAllowedCLSID(16,0) = "{F08C5AC2-E722-4116-ADB7-CE41B527994B}" : arAllowedCLSID(16,1) = "bthprops.cpl"
arAllowedCLSID(17,0) = "{F20487CC-FC04-4B1E-863F-D9801796130B}" : arAllowedCLSID(17,1) = "SyncCenter.dll"
arAllowedCLSID(18,0) = "{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}" : arAllowedCLSID(18,1) = "Actioncenter.dll"
arAllowedCLSID(19,0) = "{fbeb8a05-beee-4442-804e-409d6c4515e9}" : arAllowedCLSID(19,1) = "shell32.dll"
arAllowedCLSID(20,0) = "{ff363bfe-4941-4179-a81c-f3f1ca72d820}" : arAllowedCLSID(20,1) = "hgcpl.dll"

'W81
arAllowedCLSID(21,0) = "{59EFE487-E5B8-4fae-9D2C-FCDF0B70CE70}" : arAllowedCLSID(21,1) = "twinui.dll"
arAllowedCLSID(22,0) = "{811F592B-CDE7-4ca4-A6D4-7BB3F60AD8FB}" : arAllowedCLSID(22,1) = "shell32.dll"
arAllowedCLSID(23,0) = "{A8CD0ADC-23D6-4B79-BCC9-D3309DF34760}" : arAllowedCLSID(23,1) = "authui.dll"

'W10
arAllowedCLSID(24,0) = "{4DC9C264-730E-4CF6-8374-70F079E4F82B}" : arAllowedCLSID(24,1) = "pwsso.dll"
arAllowedCLSID(25,0) = "{78DE489B-7931-4f14-83B4-C56D38AC9FFA}" : arAllowedCLSID(25,1) = "shell32.dll"
arAllowedCLSID(26,0) = "{811F592B-CDE7-4ca4-A6D4-7BB3F60AD8FB}" : arAllowedCLSID(26,1) = "windows.storage.dll"
arAllowedCLSID(27,0) = "{872f8dc8-dde4-43bd-ac7a-e3d9fe86ceac}" : arAllowedCLSID(27,1) = "SystemResetSSO.dll"
arAllowedCLSID(28,0) = "{B5CFEB0E-9C01-4942-A5CB-F62EB09D808F}" : arAllowedCLSID(28,1) = "SettingMonitor.dll"
arAllowedCLSID(29,0) = "{D46A0B4F-4EEC-4A83-8DE5-9C86F0DFA34D}" : arAllowedCLSID(29,1) = "SettingMonitor.dll"

'arAllowedCLSID(30,0) = "" : arAllowedCLSID(30,1) = ""

arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects" )
intHKE = 3  'HKCU...SW + HKLM...SW = 1 + 2

If intBits = 64 Then

 arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects", _
  "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects")

 intHKE = 11  'HKCU...SW + HKLM...SW + HKLM...SW\Wow = 1 + 2 + 8
              'omit HKCU...SW\Wow

End If

'for every arKey member
For intKey = 0 To UBound(arKeys)

 'for each hive
 For i = intCLL To 1

  'respect Hive Key Enabler map
  If HKInclude(intHKE,i,intKey) Then

   strSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

   'find all the subkeys
   oReg.EnumKey arHives(i,1), arKeys(intKey), arSubKeys

   'enumerate data if present
   If IsArray(arSubKeys) Then

    'for each key
    For Each strCLSID In arSubKeys

     flagMatch = False

     'find CLSID title & IPSDLL
     flagWOW = False
     If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True
     ResolveCLSID strCLSID, arHives(i,1), strCLSIDTitle, strIPSDLL, flagWOW

     If strIPSDLL <> "" Then

      'find CN
      strCN = CoName(IDExe(strIPSDLL))

      'check for allowed GUID
      For j = 0 To UBound(arAllowedCLSID,1)

       'toggle match flag if allowed CLSID, allowed IPSDLL, CoName = MS
       If Not flagShowAll And LCase(strCLSID) = LCase(arAllowedCLSID(j,0)) And _
        Fso.GetFileName(LCase(strIPSDLL)) = LCase(arAllowedCLSID(j,1)) And _
        strCN = MS Then
         flagMatch = True : Exit For
       End If

      Next  'arAllowedCLSID member

      If Not flagMatch Or flagShowAll Then

       'output title line if not already done
       TitleLineWrite

       oFN.WriteLine vbCRLF & strCLSID

       strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
       If flagWOW Then
        strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
       End IF

       'output CLSID title, InProcServer32 DLL & CoName
       oFN.WriteLine "  -> {" & arHives(i,0) & strCTHL &_
        strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
        strIPSDLL & strCN

      End If  'not flagMatch Or ShowAll?

     End If  'MT strIPSDLL?

    Next  'SSO CLSID

   Else  'no SSO subkey array for this hive

    If flagShowAll Then TitleLineWrite

   End If  'SSO subkeys exist?

  End If  'HKInclude

 Next  'hive

Next  'arKeys member

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arAllowedCLSID(0,0)

End If  'SecTest?




'#6. HKCU/HKLM/HKLM-WOW... Shell Extensions\Approved\

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'CLSID value, InProcessServer32 DLL name & output file version,
'CLSID Key Title display flag
Dim strCLSID, strIPSDLLOut, strCLSIDTitle, strLocTitle

'Shell Extension Approved array
Dim arSEA() : ReDim arSEA(430,1)
'WXP
arSEA(0,0) = "{00022613-0000-0000-C000-000000000046}" : arSEA(0,1) = "mmsys.cpl"
arSEA(1,0) = "{176d6597-26d3-11d1-b350-080036a75b03}" : arSEA(1,1) = "icmui.dll"
arSEA(2,0) = "{1F2E5C40-9550-11CE-99D2-00AA006E086C}" : arSEA(2,1) = "rshx32.dll"
arSEA(3,0) = "{3EA48300-8CF6-101B-84FB-666CCB9BCD32}" : arSEA(3,1) = "docprop.dll"
arSEA(4,0) = "{40dd6e20-7c17-11ce-a804-00aa003ca9f6}" : arSEA(4,1) = "ntshrui.dll"
arSEA(5,0) = "{41E300E0-78B6-11ce-849B-444553540000}" : arSEA(5,1) = "themeui.dll"
arSEA(6,0) = "{42071712-76d4-11d1-8b24-00a0c9068ff3}" : arSEA(6,1) = "deskadp.dll"
arSEA(7,0) = "{42071713-76d4-11d1-8b24-00a0c9068ff3}" : arSEA(7,1) = "deskmon.dll"
arSEA(8,0) = "{42071714-76d4-11d1-8b24-00a0c9068ff3}" : arSEA(8,1) = "deskpan.dll"
arSEA(9,0) = "{4E40F770-369C-11d0-8922-00A024AB2DBB}" : arSEA(9,1) = "dssec.dll"
arSEA(10,0) = "{513D916F-2A8E-4F51-AEAB-0CBC76FB1AF8}" : arSEA(10,1) = "SlayerXP.dll"
arSEA(11,0) = "{56117100-C0CD-101B-81E2-00AA004AE837}" : arSEA(11,1) = "shscrap.dll"
arSEA(12,0) = "{59099400-57FF-11CE-BD94-0020AF85B590}" : arSEA(12,1) = "diskcopy.dll"
arSEA(13,0) = "{59be4990-f85c-11ce-aff7-00aa003ca9f6}" : arSEA(13,1) = "ntlanui2.dll"
arSEA(14,0) = "{5DB2625A-54DF-11D0-B6C4-0800091AA605}" : arSEA(14,1) = "icmui.dll"
arSEA(15,0) = "{675F097E-4C4D-11D0-B6C1-0800091AA605}" : arSEA(15,1) = "icmui.dll"
arSEA(16,0) = "{764BF0E1-F219-11ce-972D-00AA00A14F56}" : arSEA(16,1) = ""
arSEA(17,0) = "{77597368-7b15-11d0-a0c2-080036af3f03}" : arSEA(17,1) = "printui.dll"
arSEA(18,0) = "{7988B573-EC89-11cf-9C00-00AA00A14F56}" : arSEA(18,1) = "dskquoui.dll"
arSEA(19,0) = "{853FE2B1-B769-11d0-9C4E-00C04FB6C6FA}" : arSEA(19,1) = ""
arSEA(20,0) = "{85BBD920-42A0-1069-A2E4-08002B30309D}" : arSEA(20,1) = "syncui.dll"
arSEA(21,0) = "{88895560-9AA2-1069-930E-00AA0030EBC8}" : arSEA(21,1) = "hticons.dll"
arSEA(22,0) = "{BD84B380-8CA2-1069-AB1D-08000948F534}" : arSEA(22,1) = "fontext.dll"
arSEA(23,0) = "{DBCE2480-C732-101B-BE72-BA78E9AD5B27}" : arSEA(23,1) = "icmui.dll"
arSEA(24,0) = "{F37C5810-4D3F-11d0-B4BF-00AA00BBB723}" : arSEA(24,1) = "rshx32.dll"
arSEA(25,0) = "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" : arSEA(25,1) = "ntshrui.dll"
arSEA(26,0) = "{f92e8c40-3d33-11d2-b1aa-080036a75b03}" : arSEA(26,1) = "deskperf.dll"
arSEA(27,0) = "{7444C717-39BF-11D1-8CD9-00C04FC29D45}" : arSEA(27,1) = "cryptext.dll"
arSEA(28,0) = "{7444C719-39BF-11D1-8CD9-00C04FC29D45}" : arSEA(28,1) = "cryptext.dll"
arSEA(29,0) = "{7007ACC7-3202-11D1-AAD2-00805FC1270E}" : arSEA(29,1) = "NETSHELL.dll"
arSEA(30,0) = "{992CFFA0-F557-101A-88EC-00DD010CCC48}" : arSEA(30,1) = "NETSHELL.dll"
arSEA(31,0) = "{E211B736-43FD-11D1-9EFB-0000F8757FCD}" : arSEA(31,1) = "wiashext.dll"
arSEA(32,0) = "{FB0C9C8A-6C50-11D1-9F1D-0000F8757FCD}" : arSEA(32,1) = "wiashext.dll"
arSEA(33,0) = "{905667aa-acd6-11d2-8080-00805f6596d2}" : arSEA(33,1) = "wiashext.dll"
arSEA(34,0) = "{3F953603-1008-4f6e-A73A-04AAC7A992F1}" : arSEA(34,1) = "wiashext.dll"
arSEA(35,0) = "{83bbcbf3-b28a-4919-a5aa-73027445d672}" : arSEA(35,1) = "wiashext.dll"
arSEA(36,0) = "{F0152790-D56E-4445-850E-4F3117DB740C}" : arSEA(36,1) = "remotepg.dll"
arSEA(37,0) = "{5F327514-6C5E-4d60-8F16-D07FA08A78ED}" : arSEA(37,1) = "wuaucpl.cpl"
arSEA(38,0) = "{60254CA5-953B-11CF-8C96-00AA00B8708C}" : arSEA(38,1) = "wshext.dll"
arSEA(39,0) = "{2206CDB2-19C1-11D1-89E0-00C04FD7A829}" : arSEA(39,1) = "oledb32.dll"
arSEA(40,0) = "{DD2110F0-9EEF-11cf-8D8E-00AA0060F5BF}" : arSEA(40,1) = "mstask.dll"
arSEA(41,0) = "{797F1E90-9EDD-11cf-8D8E-00AA0060F5BF}" : arSEA(41,1) = "mstask.dll"
arSEA(42,0) = "{D6277990-4C6A-11CF-8D87-00AA0060F5BF}" : arSEA(42,1) = "mstask.dll"
arSEA(43,0) = "{0DF44EAA-FF21-4412-828E-260A8728E7F1}" : arSEA(43,1) = ""
arSEA(44,0) = "{2559a1f0-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(44,1) = "shdocvw.dll"
arSEA(45,0) = "{2559a1f1-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(45,1) = "shdocvw.dll"
arSEA(46,0) = "{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(46,1) = "shdocvw.dll"
arSEA(47,0) = "{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(47,1) = "shdocvw.dll"
arSEA(48,0) = "{2559a1f4-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(48,1) = "shdocvw.dll"
arSEA(49,0) = "{2559a1f5-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(49,1) = "shdocvw.dll"
arSEA(50,0) = "{D20EA4E1-3957-11d2-A40B-0C5020524152}" : arSEA(50,1) = "shdocvw.dll"
arSEA(51,0) = "{D20EA4E1-3957-11d2-A40B-0C5020524153}" : arSEA(51,1) = "shdocvw.dll"
arSEA(52,0) = "{875CB1A1-0F29-45de-A1AE-CFB4950D0B78}" : arSEA(52,1) = "shmedia.dll"
arSEA(53,0) = "{40C3D757-D6E4-4b49-BB41-0E5BBEA28817}" : arSEA(53,1) = "shmedia.dll"
arSEA(54,0) = "{E4B29F9D-D390-480b-92FD-7DDB47101D71}" : arSEA(54,1) = "shmedia.dll"
arSEA(55,0) = "{87D62D94-71B3-4b9a-9489-5FE6850DC73E}" : arSEA(55,1) = "shmedia.dll"
arSEA(56,0) = "{A6FD9E45-6E44-43f9-8644-08598F5A74D9}" : arSEA(56,1) = "shmedia.dll"
arSEA(57,0) = "{c5a40261-cd64-4ccf-84cb-c394da41d590}" : arSEA(57,1) = "shmedia.dll"
arSEA(58,0) = "{5E6AB780-7743-11CF-A12B-00AA004AE837}" : arSEA(58,1) = "browseui.dll"
arSEA(59,0) = "{22BF0C20-6DA7-11D0-B373-00A0C9034938}" : arSEA(59,1) = "browseui.dll"
arSEA(60,0) = "{91EA3F8B-C99B-11d0-9815-00C04FD91972}" : arSEA(60,1) = "browseui.dll"
arSEA(61,0) = "{6413BA2C-B461-11d1-A18A-080036B11A03}" : arSEA(61,1) = "browseui.dll"
arSEA(62,0) = "{F61FFEC1-754F-11d0-80CA-00AA005B4383}" : arSEA(62,1) = "browseui.dll"
arSEA(63,0) = "{7BA4C742-9E81-11CF-99D3-00AA004AE837}" : arSEA(63,1) = "browseui.dll"
arSEA(64,0) = "{30D02401-6A81-11d0-8274-00C04FD5AE38}" : arSEA(64,1) = "browseui.dll"
arSEA(65,0) = "{32683183-48a0-441b-a342-7c2a440a9478}" : arSEA(65,1) = "browseui.dll"
arSEA(66,0) = "{169A0691-8DF9-11d1-A1C4-00C04FD75D13}" : arSEA(66,1) = "browseui.dll"
arSEA(67,0) = "{07798131-AF23-11d1-9111-00A0C98BA67D}" : arSEA(67,1) = "browseui.dll"
arSEA(68,0) = "{AF4F6510-F982-11d0-8595-00AA004CD6D8}" : arSEA(68,1) = "browseui.dll"
arSEA(69,0) = "{01E04581-4EEE-11d0-BFE9-00AA005B4383}" : arSEA(69,1) = "browseui.dll"
arSEA(70,0) = "{A08C11D2-A228-11d0-825B-00AA005B4383}" : arSEA(70,1) = "browseui.dll"
arSEA(71,0) = "{00BB2763-6A77-11D0-A535-00C04FD7D062}" : arSEA(71,1) = "browseui.dll"
arSEA(72,0) = "{7376D660-C583-11d0-A3A5-00C04FD706EC}" : arSEA(72,1) = "browseui.dll"
arSEA(73,0) = "{6756A641-DE71-11d0-831B-00AA005B4383}" : arSEA(73,1) = "browseui.dll"
arSEA(74,0) = "{6935DB93-21E8-4ccc-BEB9-9FE3C77A297A}" : arSEA(74,1) = "browseui.dll"
arSEA(75,0) = "{7e653215-fa25-46bd-a339-34a2790f3cb7}" : arSEA(75,1) = "browseui.dll"
arSEA(76,0) = "{acf35015-526e-4230-9596-becbe19f0ac9}" : arSEA(76,1) = "browseui.dll"
arSEA(77,0) = "{E0E11A09-5CB8-4B6C-8332-E00720A168F2}" : arSEA(77,1) = "browseui.dll"
arSEA(78,0) = "{00BB2764-6A77-11D0-A535-00C04FD7D062}" : arSEA(78,1) = "browseui.dll"
arSEA(79,0) = "{03C036F1-A186-11D0-824A-00AA005B4383}" : arSEA(79,1) = "browseui.dll"
arSEA(80,0) = "{00BB2765-6A77-11D0-A535-00C04FD7D062}" : arSEA(80,1) = "browseui.dll"
arSEA(81,0) = "{ECD4FC4E-521C-11D0-B792-00A0C90312E1}" : arSEA(81,1) = "browseui.dll"
arSEA(82,0) = "{3CCF8A41-5C85-11d0-9796-00AA00B90ADF}" : arSEA(82,1) = "browseui.dll"
arSEA(83,0) = "{ECD4FC4C-521C-11D0-B792-00A0C90312E1}" : arSEA(83,1) = "browseui.dll"
arSEA(84,0) = "{ECD4FC4D-521C-11D0-B792-00A0C90312E1}" : arSEA(84,1) = "browseui.dll"
arSEA(85,0) = "{DD313E04-FEFF-11d1-8ECD-0000F87A470C}" : arSEA(85,1) = "browseui.dll"
arSEA(86,0) = "{EF8AD2D1-AE36-11D1-B2D2-006097DF8C11}" : arSEA(86,1) = "browseui.dll"
arSEA(87,0) = "{EFA24E61-B078-11d0-89E4-00C04FC9E26E}" : arSEA(87,1) = "shdocvw.dll"
arSEA(88,0) = "{0A89A860-D7B1-11CE-8350-444553540000}" : arSEA(88,1) = "shdocvw.dll"
arSEA(89,0) = "{E7E4BC40-E76A-11CE-A9BB-00AA004AE837}" : arSEA(89,1) = "shdocvw.dll"
arSEA(90,0) = "{A5E46E3A-8849-11D1-9D8C-00C04FC99D61}" : arSEA(90,1) = "shdocvw.dll"
arSEA(91,0) = "{FBF23B40-E3F0-101B-8488-00AA003E56F8}" : arSEA(91,1) = "shdocvw.dll"
arSEA(92,0) = "{3C374A40-BAE4-11CF-BF7D-00AA006946EE}" : arSEA(92,1) = "shdocvw.dll"
arSEA(93,0) = "{FF393560-C2A7-11CF-BFF4-444553540000}" : arSEA(93,1) = "shdocvw.dll"
arSEA(94,0) = "{7BD29E00-76C1-11CF-9DD0-00A0C9034933}" : arSEA(94,1) = "shdocvw.dll"
arSEA(95,0) = "{7BD29E01-76C1-11CF-9DD0-00A0C9034933}" : arSEA(95,1) = "shdocvw.dll"
arSEA(96,0) = "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}" : arSEA(96,1) = "shdocvw.dll"
arSEA(97,0) = "{A2B0DD40-CC59-11d0-A3A5-00C04FD706EC}" : arSEA(97,1) = "shdocvw.dll"
arSEA(98,0) = "{67EA19A0-CCEF-11d0-8024-00C04FD75D13}" : arSEA(98,1) = "shdocvw.dll"
arSEA(99,0) = "{131A6951-7F78-11D0-A979-00C04FD705A2}" : arSEA(99,1) = "shdocvw.dll"
arSEA(100,0) = "{9461b922-3c5a-11d2-bf8b-00c04fb93661}" : arSEA(100,1) = "shdocvw.dll"
arSEA(101,0) = "{3DC7A020-0ACD-11CF-A9BB-00AA004AE837}" : arSEA(101,1) = "shdocvw.dll"
arSEA(102,0) = "{871C5380-42A0-1069-A2EA-08002B30309D}" : arSEA(102,1) = "shdocvw.dll"
arSEA(103,0) = "{EFA24E64-B078-11d0-89E4-00C04FC9E26E}" : arSEA(103,1) = "shdocvw.dll"
arSEA(104,0) = "{9E56BE60-C50F-11CF-9A2C-00A0C90A90CE}" : arSEA(104,1) = "sendmail.dll"
arSEA(105,0) = "{9E56BE61-C50F-11CF-9A2C-00A0C90A90CE}" : arSEA(105,1) = "sendmail.dll"
arSEA(106,0) = "{88C6C381-2E85-11D0-94DE-444553540000}" : arSEA(106,1) = "occache.dll"
arSEA(107,0) = "{E6FB5E20-DE35-11CF-9C87-00AA005127ED}" : arSEA(107,1) = "webcheck.dll"
arSEA(108,0) = "{ABBE31D0-6DAE-11D0-BECA-00C04FD940BE}" : arSEA(108,1) = "webcheck.dll"
arSEA(109,0) = "{F5175861-2688-11d0-9C5E-00AA00A45957}" : arSEA(109,1) = "webcheck.dll"
arSEA(110,0) = "{08165EA0-E946-11CF-9C87-00AA005127ED}" : arSEA(110,1) = "webcheck.dll"
arSEA(111,0) = "{E3A8BDE6-ABCE-11d0-BC4B-00C04FD929DB}" : arSEA(111,1) = "webcheck.dll"
arSEA(112,0) = "{E8BB6DC0-6B4E-11d0-92DB-00A0C90C2BD7}" : arSEA(112,1) = "webcheck.dll"
arSEA(113,0) = "{7D559C10-9FE9-11d0-93F7-00AA0059CE02}" : arSEA(113,1) = "webcheck.dll"
arSEA(114,0) = "{E6CC6978-6B6E-11D0-BECA-00C04FD940BE}" : arSEA(114,1) = "webcheck.dll"
arSEA(115,0) = "{D8BD2030-6FC9-11D0-864F-00AA006809D9}" : arSEA(115,1) = "webcheck.dll"
arSEA(116,0) = "{7FC0B86E-5FA7-11d1-BC7C-00C04FD929DB}" : arSEA(116,1) = "webcheck.dll"
arSEA(117,0) = "{352EC2B7-8B9A-11D1-B8AE-006008059382}" : arSEA(117,1) = "appwiz.cpl"
arSEA(118,0) = "{0B124F8F-91F0-11D1-B8B5-006008059382}" : arSEA(118,1) = "appwiz.cpl"
arSEA(119,0) = "{CFCCC7A0-A282-11D1-9082-006008059382}" : arSEA(119,1) = "appwiz.cpl"
arSEA(120,0) = "{e84fda7c-1d6a-45f6-b725-cb260c236066}" : arSEA(120,1) = "shimgvw.dll"
arSEA(121,0) = "{66e4e4fb-f385-4dd0-8d74-a2efd1bc6178}" : arSEA(121,1) = "shimgvw.dll"
arSEA(122,0) = "{3F30C968-480A-4C6C-862D-EFC0897BB84B}" : arSEA(122,1) = "shimgvw.dll"
arSEA(123,0) = "{9DBD2C50-62AD-11d0-B806-00C04FD706EC}" : arSEA(123,1) = "shimgvw.dll"
arSEA(124,0) = "{EAB841A0-9550-11cf-8C16-00805F1408F3}" : arSEA(124,1) = "shimgvw.dll"
arSEA(125,0) = "{eb9b1153-3b57-4e68-959a-a3266bc3d7fe}" : arSEA(125,1) = "shimgvw.dll"
arSEA(126,0) = "{CC6EEFFB-43F6-46c5-9619-51D571967F7D}" : arSEA(126,1) = "netplwiz.dll"
arSEA(127,0) = "{add36aa8-751a-4579-a266-d66f5202ccbb}" : arSEA(127,1) = "netplwiz.dll"
arSEA(128,0) = "{6b33163c-76a5-4b6c-bf21-45de9cd503a1}" : arSEA(128,1) = "netplwiz.dll"
arSEA(129,0) = "{58f1f272-9240-4f51-b6d4-fd63d1618591}" : arSEA(129,1) = "netplwiz.dll"
arSEA(130,0) = "{7A9D77BD-5403-11d2-8785-2E0420524153}" : arSEA(130,1) = ""
arSEA(131,0) = "{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}" : arSEA(131,1) = "zipfldr.dll"
arSEA(132,0) = "{BD472F60-27FA-11cf-B8B4-444553540000}" : arSEA(132,1) = "zipfldr.dll"
arSEA(133,0) = "{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}" : arSEA(133,1) = "zipfldr.dll"
arSEA(134,0) = "{f39a0dc0-9cc8-11d0-a599-00c04fd64433}" : arSEA(134,1) = "cdfview.dll"
arSEA(135,0) = "{f3aa0dc0-9cc8-11d0-a599-00c04fd64434}" : arSEA(135,1) = "cdfview.dll"
arSEA(136,0) = "{f3ba0dc0-9cc8-11d0-a599-00c04fd64435}" : arSEA(136,1) = "cdfview.dll"
arSEA(137,0) = "{f3da0dc0-9cc8-11d0-a599-00c04fd64437}" : arSEA(137,1) = "cdfview.dll"
arSEA(138,0) = "{f3ea0dc0-9cc8-11d0-a599-00c04fd64438}" : arSEA(138,1) = "cdfview.dll"
arSEA(139,0) = "{63da6ec0-2e98-11cf-8d82-444553540000}" : arSEA(139,1) = "msieftp.dll"
arSEA(140,0) = "{883373C3-BF89-11D1-BE35-080036B11A03}" : arSEA(140,1) = "docprop2.dll"
arSEA(141,0) = "{A9CF0EAE-901A-4739-A481-E35B73E47F6D}" : arSEA(141,1) = "docprop2.dll"
arSEA(142,0) = "{8EE97210-FD1F-4B19-91DA-67914005F020}" : arSEA(142,1) = "docprop2.dll"
arSEA(143,0) = "{0EEA25CC-4362-4A12-850B-86EE61B0D3EB}" : arSEA(143,1) = "docprop2.dll"
arSEA(144,0) = "{6A205B57-2567-4A2C-B881-F787FAB579A3}" : arSEA(144,1) = "docprop2.dll"
arSEA(145,0) = "{28F8A4AC-BBB3-4D9B-B177-82BFC914FA33}" : arSEA(145,1) = "docprop2.dll"
arSEA(146,0) = "{8A23E65E-31C2-11d0-891C-00A024AB2DBB}" : arSEA(146,1) = "dsquery.dll"
arSEA(147,0) = "{9E51E0D0-6E0F-11d2-9601-00C04FA31A86}" : arSEA(147,1) = "dsquery.dll"
arSEA(148,0) = "{163FDC20-2ABC-11d0-88F0-00A024AB2DBB}" : arSEA(148,1) = "dsquery.dll"
arSEA(149,0) = "{F020E586-5264-11d1-A532-0000F8757D7E}" : arSEA(149,1) = "dsquery.dll"
arSEA(150,0) = "{0D45D530-764B-11d0-A1CA-00AA00C16E65}" : arSEA(150,1) = "dsuiext.dll"
arSEA(151,0) = "{62AE1F9A-126A-11D0-A14B-0800361B1103}" : arSEA(151,1) = "dsuiext.dll"
arSEA(152,0) = "{ECF03A33-103D-11d2-854D-006008059367}" : arSEA(152,1) = "mydocs.dll"
arSEA(153,0) = "{ECF03A32-103D-11d2-854D-006008059367}" : arSEA(153,1) = "mydocs.dll"
arSEA(154,0) = "{4a7ded0a-ad25-11d0-98a8-0800361b1103}" : arSEA(154,1) = "mydocs.dll"
arSEA(155,0) = "{750fdf0e-2a26-11d1-a3ea-080036587f03}" : arSEA(155,1) = "cscui.dll"
arSEA(156,0) = "{10CFC467-4392-11d2-8DB4-00C04FA31A66}" : arSEA(156,1) = "cscui.dll"
arSEA(157,0) = "{AFDB1F70-2A4C-11d2-9039-00C04F8EEB3E}" : arSEA(157,1) = "cscui.dll"
arSEA(158,0) = "{143A62C8-C33B-11D1-84FE-00C04FA34A14}" : arSEA(158,1) = "agentpsh.dll"
arSEA(159,0) = "{ECCDF543-45CC-11CE-B9BF-0080C87CDBA6}" : arSEA(159,1) = "dfsshlex.dll"
arSEA(160,0) = "{60fd46de-f830-4894-a628-6fa81bc0190d}" : arSEA(160,1) = "photowiz.dll"
arSEA(161,0) = "{7A80E4A8-8005-11D2-BCF8-00C04F72C717}" : arSEA(161,1) = "mmcshext.dll"
arSEA(162,0) = "{0CD7A5C0-9F37-11CE-AE65-08002B2E1262}" : arSEA(162,1) = "cabview.dll"
arSEA(163,0) = "{32714800-2E5F-11d0-8B85-00AA0044F941}" : arSEA(163,1) = "wabfind.dll"
arSEA(164,0) = "{8DD448E6-C188-4aed-AF92-44956194EB1F}" : arSEA(164,1) = "wmpshell.dll"
arSEA(165,0) = "{CE3FB1D1-02AE-4a5f-A6E9-D9F1B4073E6C}" : arSEA(165,1) = "wmpshell.dll"
arSEA(166,0) = "{F1B9284F-E9DC-4e68-9D7E-42362A59F0FD}" : arSEA(166,1) = "wmpshell.dll"
'W2K
arSEA(167,0) = "{41E300E0-78B6-11ce-849B-444553540000}" : arSEA(167,1) = "plustab.dll"
arSEA(168,0) = "{1A9BA3A0-143A-11CF-8350-444553540000}" : arSEA(168,1) = "shell32.dll"
arSEA(169,0) = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" : arSEA(169,1) = "shell32.dll"
arSEA(170,0) = "{86747AC0-42A0-1069-A2E6-08002B30309D}" : arSEA(170,1) = "shell32.dll"
arSEA(171,0) = "{0AFACED1-E828-11D1-9187-B532F1E9575D}" : arSEA(171,1) = "shell32.dll"
arSEA(172,0) = "{12518493-00B2-11d2-9FA5-9E3420524153}" : arSEA(172,1) = "shell32.dll"
arSEA(173,0) = "{21B22460-3AEA-1069-A2DC-08002B30309D}" : arSEA(173,1) = "shell32.dll"
arSEA(174,0) = "{B091E540-83E3-11CF-A713-0020AFD79762}" : arSEA(174,1) = "shell32.dll"
arSEA(175,0) = "{FBF23B41-E3F0-101B-8488-00AA003E56F8}" : arSEA(175,1) = "shell32.dll"
arSEA(176,0) = "{C2FBB630-2971-11d1-A18C-00C04FD75D13}" : arSEA(176,1) = "shell32.dll"
arSEA(177,0) = "{C2FBB631-2971-11d1-A18C-00C04FD75D13}" : arSEA(177,1) = "shell32.dll"
arSEA(178,0) = "{13709620-C279-11CE-A49E-444553540000}" : arSEA(178,1) = "shell32.dll"
arSEA(179,0) = "{62112AA1-EBE4-11cf-A5FB-0020AFE7292D}" : arSEA(179,1) = "shell32.dll"
arSEA(180,0) = "{4622AD11-FF23-11d0-8D34-00A0C90F2719}" : arSEA(180,1) = "shell32.dll"
arSEA(181,0) = "{7BA4C740-9E81-11CF-99D3-00AA004AE837}" : arSEA(181,1) = "shell32.dll"
arSEA(182,0) = "{D969A300-E7FF-11d0-A93B-00A0C90F2719}" : arSEA(182,1) = "shell32.dll"
arSEA(183,0) = "{09799AFB-AD67-11d1-ABCD-00C04FC30936}" : arSEA(183,1) = "shell32.dll"
arSEA(184,0) = "{3FC0B520-68A9-11D0-8D77-00C04FD70822}" : arSEA(184,1) = "shell32.dll"
arSEA(185,0) = "{75048700-EF1F-11D0-9888-006097DEACF9}" : arSEA(185,1) = "shell32.dll"
arSEA(186,0) = "{6D5313C0-8C62-11D1-B2CD-006097DF8C11}" : arSEA(186,1) = "shell32.dll"
arSEA(187,0) = "{57651662-CE3E-11D0-8D77-00C04FC99D61}" : arSEA(187,1) = "shell32.dll"
arSEA(188,0) = "{4657278A-411B-11d2-839A-00C04FD918D0}" : arSEA(188,1) = "shell32.dll"
arSEA(189,0) = "{A470F8CF-A1E8-4f65-8335-227475AA5C46}" : arSEA(189,1) = "shell32.dll"
arSEA(190,0) = "{568804CA-CBD7-11d0-9816-00C04FD91972}" : arSEA(190,1) = "browseui.dll"
arSEA(191,0) = "{5b4dae26-b807-11d0-9815-00c04fd91972}" : arSEA(191,1) = "browseui.dll"
arSEA(192,0) = "{8278F931-2A3E-11d2-838F-00C04FD918D0}" : arSEA(192,1) = "browseui.dll"
arSEA(193,0) = "{E13EF4E4-D2F2-11d0-9816-00C04FD91972}" : arSEA(193,1) = "browseui.dll"
arSEA(194,0) = "{ECD4FC4F-521C-11D0-B792-00A0C90312E1}" : arSEA(194,1) = "browseui.dll"
arSEA(195,0) = "{D82BE2B0-5764-11D0-A96E-00C04FD705A2}" : arSEA(195,1) = "browseui.dll"
arSEA(196,0) = "{0E5CBF21-D15F-11d0-8301-00AA005B4383}" : arSEA(196,1) = "browseui.dll"
arSEA(197,0) = "{7487cd30-f71a-11d0-9ea7-00805f714772}" : arSEA(197,1) = "browseui.dll"
arSEA(198,0) = "{8BEBB290-52D0-11D0-B7F4-00C04FD706EC}" : arSEA(198,1) = "thumbvw.dll"
arSEA(199,0) = "{EAB841A0-9550-11CF-8C16-00805F1408F3}" : arSEA(199,1) = "thumbvw.dll"
arSEA(200,0) = "{1AEB1360-5AFC-11D0-B806-00C04FD706EC}" : arSEA(200,1) = "thumbvw.dll"
arSEA(201,0) = "{9DBD2C50-62AD-11D0-B806-00C04FD706EC}" : arSEA(201,1) = "thumbvw.dll"
arSEA(202,0) = "{500202A0-731E-11D0-B829-00C04FD706EC}" : arSEA(202,1) = "thumbvw.dll"
arSEA(203,0) = "{0B124F8C-91F0-11D1-B8B5-006008059382}" : arSEA(203,1) = "appwiz.cpl"
arSEA(204,0) = "{fe1290f0-cfbd-11cf-a330-00aa00c16e65}" : arSEA(204,1) = "dsfolder.dll"
arSEA(205,0) = "{9E51E0D0-6E0F-11d2-9601-00C04FA31A86}" : arSEA(205,1) = "dsfolder.dll"
arSEA(206,0) = "{450D8FBA-AD25-11D0-98A8-0800361B1103}" : arSEA(206,1) = "mydocs.dll"
'WXP SP2
arSEA(207,0) = "{2559a1f7-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(207,1) = "shdocvw.dll"
arSEA(208,0) = "{596AB062-B4D2-4215-9F74-E9109B0A8153}" : arSEA(208,1) = "twext.dll"
arSEA(209,0) = "{9DB7A13C-F208-4981-8353-73CC61AE2783}" : arSEA(209,1) = "twext.dll"
arSEA(210,0) = "{692F0339-CBAA-47e6-B5B5-3B84DB604E87}" : arSEA(210,1) = "extmgr.dll"
'NT4
arSEA(211,0) = "{764BF0E1-F219-11ce-972D-00AA00A14F56}" : arSEA(211,1) = "shcompui.dll"
arSEA(212,0) = "{8DE56A0D-E58B-41FE-9F80-3563CDCB2C22}" : arSEA(212,1) = "thumbvw.dll"
arSEA(213,0) = "{13709620-C279-11CE-A49E-444553540000}" : arSEA(213,1) = "SHDOC401.DLL"
arSEA(214,0) = "{62112AA1-EBE4-11cf-A5FB-0020AFE7292D}" : arSEA(214,1) = "SHDOC401.DLL"
arSEA(215,0) = "{7BA4C740-9E81-11CF-99D3-00AA004AE837}" : arSEA(215,1) = "SHDOC401.DLL"
arSEA(216,0) = "{D969A300-E7FF-11d0-A93B-00A0C90F2719}" : arSEA(216,1) = "SHDOC401.DLL"
arSEA(217,0) = "{4622AD11-FF23-11d0-8D34-00A0C90F2719}" : arSEA(217,1) = "SHDOC401.DLL"
arSEA(218,0) = "{3AD1E410-AAB9-11d0-89D7-00C04FC9E26E}" : arSEA(218,1) = "SHDOCVW.DLL"
arSEA(219,0) = "{57651662-CE3E-11D0-8D77-00C04FC99D61}" : arSEA(219,1) = "SHDOC401.DLL"
arSEA(220,0) = "{B091E540-83E3-11CF-A713-0020AFD79762}" : arSEA(220,1) = "SHDOC401.DLL"
arSEA(221,0) = "{3FC0B520-68A9-11D0-8D77-00C04FD70822}" : arSEA(221,1) = "SHDOC401.DLL"
arSEA(222,0) = "{7D688A77-C613-11D0-999B-00C04FD655E1}" : arSEA(222,1) = "SHELL32.dll"
arSEA(223,0) = "{BDEADF00-C265-11d0-BCED-00A0C90AB50F}" : arSEA(223,1) = "MSONSEXT.DLL"
arSEA(224,0) = "{C2FBB630-2971-11d1-A18C-00C04FD75D13}" : arSEA(224,1) = "SHDOC401.DLL"
arSEA(225,0) = "{C2FBB631-2971-11d1-A18C-00C04FD75D13}" : arSEA(225,1) = "SHDOC401.DLL"
arSEA(226,0) = "{75048700-EF1F-11D0-9888-006097DEACF9}" : arSEA(226,1) = "SHDOC401.DLL"
arSEA(227,0) = "{6D5313C0-8C62-11D1-B2CD-006097DF8C11}" : arSEA(227,1) = "SHDOC401.DLL"
arSEA(228,0) = "{FBF23B41-E3F0-101B-8488-00AA003E56F8}" : arSEA(228,1) = "SHDOC401.DLL"
arSEA(229,0) = "{5a61f7a0-cde1-11cf-9113-00aa00425c62}" : arSEA(229,1) = "w3ext.dll"
'WMe
arSEA(230,0) = "{3F30C968-480A-4C6C-862D-EFC0897BB84B}" : arSEA(230,1) = "THUMBVW.DLL"  'see (122)
arSEA(231,0) = "{53C74826-AB99-4d33-ACA4-3117F51D3788}" : arSEA(231,1) = "SHELL32.DLL"
arSEA(232,0) = "{992CFFA0-F557-101A-88EC-00DD010CCC48}" : arSEA(232,1) = "rnaui.dll"  'see (30)
arSEA(233,0) = "{FEF10FA2-355E-4e06-9381-9B24D7F7CC88}" : arSEA(233,1) = "SHELL32.DLL"
'MS PowerToys
arSEA(234,0) = "{AA7C7080-860A-11CE-8424-08002B2CFF76}" : arSEA(234,1) = "SENDTOX.DLL"
arSEA(235,0) = "{7BB70120-6C78-11CF-BFC7-444553540000}" : arSEA(235,1) = "SENDTOX.DLL"
arSEA(236,0) = "{7BB70122-6C78-11CF-BFC7-444553540000}" : arSEA(236,1) = "SENDTOX.DLL"
arSEA(237,0) = "{7BB70121-6C78-11CF-BFC7-444553540000}" : arSEA(237,1) = "SENDTOX.DLL"
arSEA(238,0) = "{7BB70123-6C78-11CF-BFC7-444553540000}" : arSEA(238,1) = "SENDTOX.DLL"
arSEA(239,0) = "{9E56BE62-C50F-11CF-9A2C-00A0C90A90CE}" : arSEA(239,1) = "SENDTOX.DLL"
arSEA(240,0) = "{90A756E0-AFCF-11CE-927B-0800095AE340}" : arSEA(240,1) = "target.dll"
arSEA(241,0) = "{afc638f0-e8a4-11ce-9ade-00aa00a42d2e}" : arSEA(241,1) = "TTFExtNT.dll"
'etc
arSEA(242,0) = "{1D2680C9-0E2A-469d-B787-065558BC7D43}" : arSEA(242,1) = "mscoree.dll"
arSEA(243,0) = "{5F327514-6C5E-4d60-8F16-D07FA08A78ED}" : arSEA(243,1) = "wuaueng.dll"
'WXP IE 7
arSEA(244,0) = "{07C45BB1-4A8C-4642-A1F5-237E7215FF66}" : arSEA(244,1) = "ieframe.dll"
arSEA(245,0) = "{1C1EDB47-CE22-4bbb-B608-77B48F83C823}" : arSEA(245,1) = "ieframe.dll"
arSEA(246,0) = "{205D7A97-F16D-4691-86EF-F3075DCCA57D}" : arSEA(246,1) = "ieframe.dll"
arSEA(247,0) = "{3028902F-6374-48b2-8DC6-9725E775B926}" : arSEA(247,1) = "ieframe.dll"
arSEA(248,0) = "{30D02401-6A81-11d0-8274-00C04FD5AE38}" : arSEA(248,1) = "ieframe.dll"
arSEA(249,0) = "{3C374A40-BAE4-11CF-BF7D-00AA006946EE}" : arSEA(249,1) = "ieframe.dll"
arSEA(250,0) = "{3DC7A020-0ACD-11CF-A9BB-00AA004AE837}" : arSEA(250,1) = "ieframe.dll"
arSEA(251,0) = "{43886CD5-6529-41c4-A707-7B3C92C05E68}" : arSEA(251,1) = "ieframe.dll"
arSEA(252,0) = "{44C76ECD-F7FA-411c-9929-1B77BA77F524}" : arSEA(252,1) = "ieframe.dll"
arSEA(253,0) = "{4B78D326-D922-44f9-AF2A-07805C2A3560}" : arSEA(253,1) = "ieframe.dll"
arSEA(254,0) = "{6038EF75-ABFC-4e59-AB6F-12D397F6568D}" : arSEA(254,1) = "ieframe.dll"
arSEA(255,0) = "{6B4ECC4F-16D1-4474-94AB-5A763F2A54AE}" : arSEA(255,1) = "ieframe.dll"
arSEA(256,0) = "{6CF48EF8-44CD-45d2-8832-A16EA016311B}" : arSEA(256,1) = "ieframe.dll"
arSEA(257,0) = "{73CFD649-CD48-4fd8-A272-2070EA56526B}" : arSEA(257,1) = "ieframe.dll"
arSEA(258,0) = "{7BD29E00-76C1-11CF-9DD0-00A0C9034933}" : arSEA(258,1) = "ieframe.dll"
arSEA(259,0) = "{7BD29E01-76C1-11CF-9DD0-00A0C9034933}" : arSEA(259,1) = "ieframe.dll"
arSEA(260,0) = "{871C5380-42A0-1069-A2EA-08002B30309D}" : arSEA(260,1) = "ieframe.dll"
arSEA(261,0) = "{98FF6D4B-6387-4b0a-8FBD-C5C4BB17B4F8}" : arSEA(261,1) = "ieframe.dll"
arSEA(262,0) = "{9a096bb5-9dc3-4d1c-8526-c3cbf991ea4e}" : arSEA(262,1) = "ieframe.dll"
arSEA(263,0) = "{9D958C62-3954-4b44-8FAB-C4670C1DB4C2}" : arSEA(263,1) = "ieframe.dll"
arSEA(264,0) = "{B31C5FAE-961F-415b-BAF0-E697A5178B94}" : arSEA(264,1) = "ieframe.dll"
arSEA(265,0) = "{BC476F4C-D9D7-4100-8D4E-E043F6DEC409}" : arSEA(265,1) = "ieframe.dll"
arSEA(266,0) = "{BFAD62EE-9D54-4b2a-BF3B-76F90697BD2A}" : arSEA(266,1) = "ieframe.dll"
arSEA(267,0) = "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}" : arSEA(267,1) = "ieframe.dll"
arSEA(268,0) = "{E6EE9AAC-F76B-4947-8260-A9F136138E11}" : arSEA(268,1) = "ieframe.dll"
arSEA(269,0) = "{E7E4BC40-E76A-11CE-A9BB-00AA004AE837}" : arSEA(269,1) = "ieframe.dll"
arSEA(270,0) = "{F0353E1D-FEEC-474e-A984-1E5C6865E380}" : arSEA(270,1) = "ieframe.dll"
arSEA(271,0) = "{F2CF5485-4E02-4f68-819C-B92DE9277049}" : arSEA(271,1) = "ieframe.dll"
arSEA(272,0) = "{F83DAC1C-9BB9-4f2b-B619-09819DA81B0E}" : arSEA(272,1) = "ieframe.dll"
arSEA(273,0) = "{FAC3CBF6-8697-43d0-BAB9-DCD1FCE19D75}" : arSEA(273,1) = "ieframe.dll"
arSEA(274,0) = "{FBF23B40-E3F0-101B-8488-00AA003E56F8}" : arSEA(274,1) = "ieframe.dll"
arSEA(275,0) = "{FDE7673D-2E19-4145-8376-BBD58C4BC7BA}" : arSEA(275,1) = "ieframe.dll"
arSEA(276,0) = "{FF393560-C2A7-11CF-BFF4-444553540000}" : arSEA(276,1) = "ieframe.dll"
'WVa
arSEA(277,0) = "{00021401-0000-0000-C000-000000000046}" : arSEA(277,1) = "shell32.dll"
arSEA(278,0) = "{00f20eb5-8fd6-4d9d-b75e-36801766c8f1}" : arSEA(278,1) = "PhotoAcq.dll"
arSEA(279,0) = "{025A5937-A6BE-4686-A844-36FE4BEC8B6D}" : arSEA(279,1) = "shdocvw.dll"
arSEA(280,0) = "{056440FD-8568-48e7-A632-72157243B55B}" : arSEA(280,1) = "browseui.dll"
arSEA(281,0) = "{0a4286ea-e355-44fb-8086-af3df7645bd9}" : arSEA(281,1) = "wmpband.dll"
arSEA(282,0) = "{0AFCCBA6-BF90-4A4E-8482-0AC960981F5B}" : arSEA(282,1) = "shell32.dll"
arSEA(283,0) = "{0BFCF7B7-E7B6-433a-B205-2904FCF040DD}" : arSEA(283,1) = "appwiz.cpl"
arSEA(284,0) = "{11dbb47c-a525-400b-9e80-a54615a090c0}" : arSEA(284,1) = "ExplorerFrame.dll"
arSEA(285,0) = "{13D3C4B8-B179-4ebb-BF62-F704173E7448}" : arSEA(285,1) = "wab32.dll"
arSEA(286,0) = "{1531d583-8375-4d3f-b5fb-d23bbd169f22}" : arSEA(286,1) = "shell32.dll"
arSEA(287,0) = "{15D633E2-AD00-465b-9EC7-F56B7CDF8E27}" : arSEA(287,1) = "TipBand.dll"
arSEA(288,0) = "{15eae92e-f17a-4431-9f28-805e482dafd4}" : arSEA(288,1) = "appwiz.cpl"
arSEA(289,0) = "{16C2C29D-0E5F-45f3-A445-03E03F587B7D}" : arSEA(289,1) = "wab32.dll"
arSEA(290,0) = "{176d6597-26d3-11d1-b350-080036a75b03}" : arSEA(290,1) = "colorui.dll"
arSEA(291,0) = "{17cd9488-1228-4b2f-88ce-4298e93e0966}" : arSEA(291,1) = "shdocvw.dll"
arSEA(292,0) = "{1a184871-359e-4f67-aad9-5b9905d62232}" : arSEA(292,1) = "fontext.dll"
arSEA(293,0) = "{1FA9085F-25A2-489B-85D4-86326EEDCD87}" : arSEA(293,1) = "wlanpref.dll"
arSEA(294,0) = "{21569614-B795-46b1-85F4-E737A8DC09AD}" : arSEA(294,1) = "browseui.dll"
arSEA(295,0) = "{21ec2020-3aea-1069-a2dd-08002b30309d}" : arSEA(295,1) = "shell32.dll"
arSEA(296,0) = "{25336920-03f9-11cf-8fd0-00aa00686f13}" : arSEA(296,1) = "mshtml.dll"
arSEA(297,0) = "{25585dc7-4da0-438d-ad04-e42c8d2d64b9}" : arSEA(297,1) = "shell32.dll"
arSEA(298,0) = "{2559a1f6-21d7-11d4-bdaf-00c04f60b9f0}" : arSEA(298,1) = "shdocvw.dll"
arSEA(299,0) = "{2781761E-28E0-4109-99FE-B9D127C57AFE}" : arSEA(299,1) = "MpOav.dll"
arSEA(300,0) = "{289978AC-A101-4341-A817-21EBA7FD046D}" : arSEA(300,1) = "SyncCenter.dll"
arSEA(301,0) = "{2BC0DA0E-F1BC-43AB-B4B5-738EB6B51E7E}" : arSEA(301,1) = "fontext.dll"
arSEA(302,0) = "{2E9E59C0-B437-4981-A647-9C34B9B90891}" : arSEA(302,1) = "SyncCenter.dll"
arSEA(303,0) = "{3050f3d9-98b5-11cf-bb82-00aa00bdce0b}" : arSEA(303,1) = "mshtml.dll"
arSEA(304,0) = "{3080F90D-D7AD-11D9-BD98-0000947B0257}" : arSEA(304,1) = "shdocvw.dll"
arSEA(305,0) = "{3080F90E-D7AD-11D9-BD98-0000947B0257}" : arSEA(305,1) = "shdocvw.dll"
arSEA(306,0) = "{328B0346-7EAF-4BBE-A479-7CB88A095F5B}" : arSEA(306,1) = "shell32.dll"
arSEA(307,0) = "{335a31dd-f04b-4d76-a925-d6b47cf360df}" : arSEA(307,1) = "shdocvw.dll"
arSEA(308,0) = "{35786D3C-B075-49b9-88DD-029876E11C01}" : arSEA(308,1) = "wpdshext.dll"
arSEA(309,0) = "{36eef7db-88ad-4e81-ad49-0e313f0c35f8}" : arSEA(309,1) = "shdocvw.dll"
arSEA(310,0) = "{3c2654c6-7372-4f6b-b310-55d6128f49d2}" : arSEA(310,1) = "shell32.dll"
arSEA(311,0) = "{3F30C968-480A-4C6C-862D-EFC0897BB84B}" : arSEA(311,1) = "PhotoMetadataHandler.dll"
arSEA(312,0) = "{40C3D757-D6E4-4b49-BB41-0E5BBEA28817}" : arSEA(312,1) = "mediametadatahandler.dll"
arSEA(313,0) = "{4336a54d-038b-4685-ab02-99bb52d3fb8b}" : arSEA(313,1) = "shdocvw.dll"
arSEA(314,0) = "{437ff9c0-a07f-4fa0-af80-84b6c6440a16}" : arSEA(314,1) = "shell32.dll"
arSEA(315,0) = "{44121072-A222-48f2-A58A-6D9AD51EBBE9}" : arSEA(315,1) = "XPSSHHDR.DLL"
arSEA(316,0) = "{44f3dab6-4392-4186-bb7b-6282ccb7a9f6}" : arSEA(316,1) = "mydocs.dll"
arSEA(317,0) = "{45670FA8-ED97-4F44-BC93-305082590BFB}" : arSEA(317,1) = "XPSSHHDR.DLL"
arSEA(318,0) = "{474C98EE-CF3D-41f5-80E3-4AAB0AB04301}" : arSEA(318,1) = "cscui.dll"
arSEA(319,0) = "{4A1E5ACD-A108-4100-9E26-D2FAFA1BA486}" : arSEA(319,1) = "icsigd.dll"
arSEA(320,0) = "{4B534112-3AF6-4697-A77C-D62CE9B9E7CF}" : arSEA(320,1) = "SyncCenter.dll"
arSEA(321,0) = "{4D1209BD-36E2-4e2f-840D-6C7FB879DD9E}" : arSEA(321,1) = "shdocvw.dll"
arSEA(322,0) = "{4d5c8c2a-d075-11d0-b416-00c04fb90376}" : arSEA(322,1) = "browseui.dll"
arSEA(323,0) = "{4E5BFBF8-F59A-4e87-9805-1F9B42CC254A}" : arSEA(323,1) = "gameux.dll"
arSEA(324,0) = "{4E77131D-3629-431c-9818-C5679DC83E81}" : arSEA(324,1) = "cscui.dll"
arSEA(325,0) = "{4F58F63F-244B-4c07-B29F-210BE59BE9B4}" : arSEA(325,1) = "wab32.dll"
arSEA(326,0) = "{513D916F-2A8E-4F51-AEAB-0CBC76FB1AF8}" : arSEA(326,1) = "acppage.dll"
arSEA(327,0) = "{53BEDF0B-4E5B-4183-8DC9-B844344FA104}" : arSEA(327,1) = "mssvp.dll"
arSEA(328,0) = "{576C9E85-1300-4EF5-BF6B-D00509F4EDCD}" : arSEA(328,1) = "SyncCenter.dll"
arSEA(329,0) = "{58E3C745-D971-4081-9034-86E34B30836A}" : arSEA(329,1) = "shdocvw.dll"
arSEA(330,0) = "{596742A5-1393-4e13-8765-AE1DF71ACAFB}" : arSEA(330,1) = "browseui.dll"
arSEA(331,0) = "{5DB2625A-54DF-11D0-B6C4-0800091AA605}" : arSEA(331,1) = "colorui.dll"
arSEA(332,0) = "{5FA29220-36A1-40f9-89C6-F4B384B7642E}" : arSEA(332,1) = "inetcomm.dll"
arSEA(333,0) = "{60632754-c523-4b62-b45c-4172da012619}" : arSEA(333,1) = "shdocvw.dll"
arSEA(334,0) = "{640167b4-59b0-47a6-b335-a6b3c0695aea}" : arSEA(334,1) = "audiodev.dll"
arSEA(335,0) = "{66742402-F9B9-11D1-A202-0000F81FEDEE}" : arSEA(335,1) = "shell32.dll"
arSEA(336,0) = "{675F097E-4C4D-11D0-B6C1-0800091AA605}" : arSEA(336,1) = "colorui.dll"
arSEA(337,0) = "{6b33163c-76a5-4b6c-bf21-45de9cd503a1}" : arSEA(337,1) = "shwebsvc.dll"
arSEA(338,0) = "{6b9228da-9c15-419e-856c-19e768a13bdc}" : arSEA(338,1) = "sbdrop.dll"
arSEA(339,0) = "{6D8BB3D3-9D87-4a91-AB56-4F30CFFEFE9F}" : arSEA(339,1) = "browseui.dll"
arSEA(340,0) = "{708e1662-b832-42a8-bbe1-0a77121e3908}" : arSEA(340,1) = "shell32.dll"
arSEA(341,0) = "{71D99464-3B6B-475C-B241-E15883207529}" : arSEA(341,1) = "SyncCenter.dll"
arSEA(342,0) = "{71f96385-ddd6-48d3-a0c1-ae06e8b055fb}" : arSEA(342,1) = "shell32.dll"
arSEA(343,0) = "{74246bfc-4c96-11d0-abef-0020af6b0b7a}" : arSEA(343,1) = "devmgr.dll"
arSEA(344,0) = "{78F3955E-3B90-4184-BD14-5397C15F1EFC}" : arSEA(344,1) = "shdocvw.dll"
arSEA(345,0) = "{7A0F6AB7-ED84-46B6-B47E-02AA159A152B}" : arSEA(345,1) = "SyncCenter.dll"
arSEA(346,0) = "{7b81be6a-ce2b-4676-a29e-eb907a5126c5}" : arSEA(346,1) = "appwiz.cpl"
arSEA(347,0) = "{7D4734E6-047E-41e2-AEAA-E763B4739DC4}" : arSEA(347,1) = "wmpshell.dll"
arSEA(348,0) = "{7EFA68C6-086B-43e1-A2D2-55A113531240}" : arSEA(348,1) = "cscui.dll"
arSEA(349,0) = "{8082C5E6-4C27-48ec-A809-B8E1122E8F97}" : arSEA(349,1) = "wab32.dll"
arSEA(350,0) = "{865e5e76-ad83-4dca-a109-50dc2113ce9a}" : arSEA(350,1) = "shell32.dll"
arSEA(351,0) = "{875CB1A1-0F29-45de-A1AE-CFB4950D0B78}" : arSEA(351,1) = "mediametadatahandler.dll"
arSEA(352,0) = "{877ca5ac-cb41-4842-9c69-9136e42d47e2}" : arSEA(352,1) = "sdshext.dll"
arSEA(353,0) = "{8856f961-340a-11d0-a96b-00c04fd705a2}" : arSEA(353,1) = "ieframe.dll"
arSEA(354,0) = "{89D83576-6BD1-4c86-9454-BEB04E94C819}" : arSEA(354,1) = "mssvp.dll"
arSEA(355,0) = "{8A734961-C4AA-4741-AC1E-791ACEBF5B39}" : arSEA(355,1) = "wmpshell.dll"
arSEA(356,0) = "{8a7cae0e-5951-49cb-bf20-ab3fa1e44b01}" : arSEA(356,1) = "fontext.dll"
arSEA(357,0) = "{8E25992B-373E-486E-80E5-BD23AE417E66}" : arSEA(357,1) = "SyncCenter.dll"
arSEA(358,0) = "{8E908FC9-BECC-40f6-915B-F4CA0E70D03D}" : arSEA(358,1) = "shdocvw.dll"
arSEA(359,0) = "{90b9bce2-b6db-4fd3-8451-35917ea1081b}" : arSEA(359,1) = "ExplorerFrame.dll"
arSEA(360,0) = "{90f8c90b-04e0-4e92-a186-e6e9c125d664}" : arSEA(360,1) = "shdocvw.dll"
arSEA(361,0) = "{91ADC906-6722-4B05-A12B-471ADDCCE132}" : arSEA(361,1) = "TouchX.dll"
arSEA(362,0) = "{92337A8C-E11D-11D0-BE48-00C04FC30DF6}" : arSEA(362,1) = "oleprn.dll"
arSEA(363,0) = "{92dbad9f-5025-49b0-9078-2d78f935e341}" : arSEA(363,1) = "inetcomm.dll"
arSEA(364,0) = "{96AE8D84-A250-4520-95A5-A47A7E3C548B}" : arSEA(364,1) = "shdocvw.dll"
arSEA(365,0) = "{97e467b4-98c6-4f19-9588-161b7773d6f6}" : arSEA(365,1) = "propsys.dll"
arSEA(366,0) = "{9C60DE1E-E5FC-40f4-A487-460851A8D915}" : arSEA(366,1) = "shdocvw.dll"
arSEA(367,0) = "{9C73F5E5-7AE7-4E32-A8E8-8D23B85255BF}" : arSEA(367,1) = "SyncCenter.dll"
arSEA(368,0) = "{9DBD2C50-62AD-11d0-B806-00C04FD706EC}" : arSEA(368,1) = "shell32.dll"
arSEA(369,0) = "{a38b883c-1682-497e-97b0-0a3a9e801682}" : arSEA(369,1) = "PhotoMetadataHandler.dll"
arSEA(370,0) = "{a42c2ccb-67d3-46fa-abe6-7d2f3488c7a3}" : arSEA(370,1) = "shell32.dll"
arSEA(371,0) = "{a542e116-8088-4146-a352-b0d06e7f6af6}" : arSEA(371,1) = "browseui.dll"
arSEA(372,0) = "{add36aa8-751a-4579-a266-d66f5202ccbb}" : arSEA(372,1) = "shwebsvc.dll"
arSEA(373,0) = "{b155bdf8-02f0-451e-9a26-ae317cfd7779}" : arSEA(373,1) = "shdocvw.dll"
arSEA(374,0) = "{b2952b16-0e07-4e5a-b993-58c52cb94cae}" : arSEA(374,1) = "shell32.dll"
arSEA(375,0) = "{B32D3949-ED98-4DBB-B347-17A144969BBA}" : arSEA(375,1) = "SyncCenter.dll"
arSEA(376,0) = "{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}" : arSEA(376,1) = "zipfldr.dll"
arSEA(377,0) = "{b9815375-5d7f-4ce2-9245-c9d4da436930}" : arSEA(377,1) = "inetcomm.dll"
arSEA(378,0) = "{BB06C0E4-D293-4f75-8A90-CB05B6477EEE}" : arSEA(378,1) = "shdocvw.dll"
arSEA(379,0) = "{BB6B2374-3D79-41DB-87F4-896C91846510}" : arSEA(379,1) = "emdmgmt.dll"
arSEA(380,0) = "{BC48B32F-5910-47F5-8570-5074A8A5636A}" : arSEA(380,1) = "SyncCenter.dll"
arSEA(381,0) = "{BC65FB43-1958-4349-971A-210290480130}" : arSEA(381,1) = "NcdProp.dll"
arSEA(382,0) = "{BD7A2E7B-21CB-41b2-A086-B309680C6B7E}" : arSEA(382,1) = "mssvp.dll"
arSEA(383,0) = "{BE122A0E-4503-11DA-8BDE-F66BAD1E3F3A}" : arSEA(383,1) = "shdocvw.dll"
arSEA(384,0) = "{C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}" : arSEA(384,1) = "comdlg32.dll"
arSEA(385,0) = "{C4EC38BD-4E9E-4b5e-935A-D1BFF237D980}" : arSEA(385,1) = "browseui.dll"
arSEA(386,0) = "{c5a40261-cd64-4ccf-84cb-c394da41d590}" : arSEA(386,1) = "mediametadatahandler.dll"
arSEA(387,0) = "{C73F6F30-97A0-4AD1-A08F-540D4E9BC7B9}" : arSEA(387,1) = "shdocvw.dll"
arSEA(388,0) = "{C7657C4A-9F68-40fa-A4DF-96BC08EB3551}" : arSEA(388,1) = "PhotoMetadataHandler.dll"
arSEA(389,0) = "{CB1B7F8C-C50A-4176-B604-9E24DEE8D4D1}" : arSEA(389,1) = "oobefldr.dll"
arSEA(390,0) = "{CC6EEFFB-43F6-46c5-9619-51D571967F7D}" : arSEA(390,1) = "shwebsvc.dll"
arSEA(391,0) = "{ceefea1b-3e29-4ef1-b34c-fec79c4f70af}" : arSEA(391,1) = "appwiz.cpl"
arSEA(392,0) = "{CF67796C-F57F-45F8-92FB-AD698826C602}" : arSEA(392,1) = "wab32.dll"
arSEA(393,0) = "{D34A6CA6-62C2-4C34-8A7C-14709C1AD938}" : arSEA(393,1) = "shdocvw.dll"
arSEA(394,0) = "{d450a8a1-9568-45c7-9c0e-b4f9fb4537bd}" : arSEA(394,1) = "appwiz.cpl"
arSEA(395,0) = "{D555645E-D4F8-4c29-A827-D93C859C4F2A}" : arSEA(395,1) = "shdocvw.dll"
arSEA(396,0) = "{D6791A63-E7E2-4fee-BF52-5DED8E86E9B8}" : arSEA(396,1) = "wpdshext.dll"
arSEA(397,0) = "{D9EF8727-CAC2-4e60-809E-86F80A666C91}" : arSEA(397,1) = "shdocvw.dll"
arSEA(398,0) = "{DBCE2480-C732-101B-BE72-BA78E9AD5B27}" : arSEA(398,1) = "colorui.dll"
arSEA(399,0) = "{DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7}" : arSEA(399,1) = "comdlg32.dll"
arSEA(400,0) = "{DFFACDC5-679F-4156-8947-C5C76BC0B67F}" : arSEA(400,1) = "shdocvw.dll"
arSEA(401,0) = "{E37E2028-CE1A-4f42-AF05-6CEABC4E5D75}" : arSEA(401,1) = "dfshim.dll"
arSEA(402,0) = "{E413D040-6788-4C22-957E-175D1C513A34}" : arSEA(402,1) = "SyncCenter.dll"
arSEA(403,0) = "{E598560B-28D5-46aa-A14A-8A3BEA34B576}" : arSEA(403,1) = "PhotoViewer.dll"
arSEA(404,0) = "{E7DE9B1A-7533-4556-9484-B26FB486475E}" : arSEA(404,1) = "shdocvw.dll"
arSEA(405,0) = "{e82a2d71-5b2f-43a0-97b8-81be15854de8}" : arSEA(405,1) = "dfshim.dll"
arSEA(406,0) = "{E95A4861-D57A-4be1-AD0F-35267E261739}" : arSEA(406,1) = "shdocvw.dll"
arSEA(407,0) = "{eb124705-128b-40d4-8dd8-d93ed12589a4}" : arSEA(407,1) = "shdocvw.dll"
arSEA(408,0) = "{ECDD6472-2B9B-4b4b-AE36-F316DF3C8D60}" : arSEA(408,1) = "gameux.dll"
arSEA(409,0) = "{ED228FDF-9EA8-4870-83B1-96B02CFE0D52}" : arSEA(409,1) = "gameux.dll"
arSEA(410,0) = "{ed50fc29-b964-48a9-afb3-15ebb9b97f36}" : arSEA(410,1) = "shdocvw.dll"
arSEA(411,0) = "{ED834ED6-4B5A-4bfe-8F11-A626DCB6A921}" : arSEA(411,1) = "shdocvw.dll"
arSEA(412,0) = "{ed9d80b9-d157-457b-9192-0e7280313bf0}" : arSEA(412,1) = "zipfldr.dll"
arSEA(413,0) = "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" : arSEA(413,1) = "NetworkExplorer.dll"
arSEA(414,0) = "{F04CC277-03A2-4277-96A9-77967471BDFF}" : arSEA(414,1) = "SyncCenter.dll"
arSEA(415,0) = "{f8b8412b-dea3-4130-b36c-5e8be73106ac}" : arSEA(415,1) = "inetcomm.dll"
arSEA(416,0) = "{F1390A9A-A3F4-4E5D-9C5F-98F3BD8D935C}" : arSEA(416,1) = "SyncCenter.dll"
arSEA(417,0) = "{fccf70c8-f4d7-4d8b-8c17-cd6715e37fff}" : arSEA(417,1) = "browseui.dll"
arSEA(418,0) = "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" : arSEA(418,1) = "PhotoViewer.dll"
arSEA(419,0) = "{28803F59-3A75-4058-995F-4EE5503B023C}" : arSEA(419,1) = "FunctionDiscoveryFolder.dll"
arSEA(420,0) = "{9113A02D-00A3-46B9-BC5F-9C04DADDD5D7}" : arSEA(420,1) = "EhStorShell.dll"
arSEA(421,0) = "{11016101-E366-4D22-BC06-4ADA335C892B}" : arSEA(421,1) = "ieframe.dll"
'Wn7
arSEA(422,0) = "{00C6D95F-329C-409a-81D7-C46C66EA7F33}" : arSEA(422,1) = "shdocvw.dll"
arSEA(423,0) = "{80009818-f38f-4af1-87b5-eadab9433e58}" : arSEA(423,1) = "mf.dll"
'WS2K3
arSEA(424,0) = "{EFA24E62-B078-11d0-89E4-00C04FC9E26E}" : arSEA(424,1) = "shdocvw.dll"
arSEA(425,0) = "{cc86590a-b60a-48e6-996b-41d25ed39a1e}" : arSEA(425,1) = "audiodev.dll"
'Wn8
arSEA(426,0) = "{289AF617-1CC3-42A6-926C-E6A863F0E3BA}" : arSEA(426,1) = "dlnashext.dll"
arSEA(427,0) = "{BFD468D2-D0A0-4bdc-878C-E69C2F5B435D}" : arSEA(427,1) = "inetcomm.dll"
arSEA(428,0) = "{3DBEE9A1-C471-4B95-BBCA-F39310064458}" : arSEA(428,1) = "MicrosoftRawCodec.dll"
'WS2K3
arSEA(429,0) = "{4648F940-EFE3-4BAB-9211-3BE45CD5029D}" : arSEA(429,1) = "vssui.dll"
'W10
arSEA(430,0) = "{3DBEE9A1-C471-4B95-BBCA-F39310064458}" : arSEA(430,1) = "WindowsCodecsRaw.dll"

arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")
intHKE = 3  'HKCU...SW + HKLM...SW = 1 + 2

If intBits = 64 Then

 arKeys = Array("Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" , _
  "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")

 intHKE = 11  'HKCU...SW + HKLM...SW + HKLM...SW\Wow = 1 + 2 + 8
              'omit HKCU...SW\Wow

End If

'for every arKey member
For intKey = 0 To UBound(arKeys)

 'for each hive
 For i = intCLL To 1

  'respect Hive Key Enabler map
  If HKInclude(intHKE,i,intKey) Then

   'assign subtitle
   strSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

   'find all the names in the key
   oReg.EnumValues arHives(i,1), arKeys(intKey), arNames, arType

   'enumerate data if present
   If IsArray(arNames) Then

     'for each CLSID
    For Each strCLSID in arNames

      flagTitle = False

      'find CLSID title
      CLSIDLocTitle arHives(i,1), arKeys(intKey), strCLSID, strLocTitle

     'for each hive
     For ctrCH = intCLL To 1

       'assume CLSID unapproved
       flagMatch = False

       flagWOW = False
       If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True
       ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

      If strIPSDLL <> "" Then

       strCN = CoName(IDExe(strIPSDLL))

       'for every member of approved shellex array in HKLM hive
       '(can't have approved shellex in HKCU)
       For j = 0 To UBound(arSEA,1)

        'if not ShowAll And CLSID's & DLL's identical And CoName = MS, shellex is known
        If Not flagShowAll And (LCase(strCLSID) = LCase(arSEA(j,0))) And _
         (Fso.GetFileName(LCase(strIPSDLL)) = LCase(arSEA(j,1))) And _
         (strCN = MS) And ctrCH = 1 Then

         'toggle flag & exit for
         flagMatch = True : Exit For

        End If

       Next  'arSEA member

       'for ShowAll Or unknown shellex
       If flagShowAll Or Not flagMatch Then

        TitleLineWrite

        If Not flagTitle Then

         'output CLSID & title
         oFN.WriteLine vbCRLF & strCLSID & " = " & strLocTitle
         flagTitle = True

        End If

        strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
        If flagWOW Then
         strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
        End IF

        'output CLSID title, InProcServer32 DLL & CoName
        oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
         strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
         strIPSDLL & strCN

       End If  'flagMatch Or flagShowAll?

      End If  'strIPSDLL <> ""?

     Next  'CLSID Hive

    Next  'strCLSID

   Else  'arNames array not returned

    'if ShowAll, output key name
    If flagShowAll Then TitleLineWrite

   End If  'intErrNum1 = 0 & arNames array exists?

  End If  'HKInclude

 Next  'hive

Next  'arKeys member

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arSEA(0,0)

End If  'SecTest?




'#7. HKLM/HKLM-WOW... Explorer\DeviceNotificationCallbacks/SharedTaskScheduler/ShellExecuteHooks

'W10: HKLM/HKLM-WOW... ShellExecuteHooks key exists, but is empty

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim ctrLow

If intBits = 32 Then

 ReDim arExpSubKeys(2)

 arExpSubKeys(0) = "Software\Microsoft\Windows\CurrentVersion\Explorer\DeviceNotificationCallbacks"
 arExpSubKeys(1) = "Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"
 arExpSubKeys(2) = "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"

 ctrLow = 1
 If strOS = "WVA" Or strOS = "WN7" Then ctrLow = 0

Else  'intBits = 64

 ReDim arExpSubKeys(5)

 arExpSubKeys(0) = "Software\Microsoft\Windows\CurrentVersion\Explorer\DeviceNotificationCallbacks"
 arExpSubKeys(1) = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\DeviceNotificationCallbacks"

 arExpSubKeys(2) = "Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"
 arExpSubKeys(3) = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"

 arExpSubKeys(4) = "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
 arExpSubKeys(5) = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"

 ctrLow = 2
 If strOS = "WVA" Or strOS = "WN7" Then ctrLow = 0

End If

'for each Explorer sub-key
'fixed bug here: needed to use "intKey" instead of "i" as counter
For intKey = ctrLow To UBound(arExpSubKeys)

 strSubTitle = SOCA("HKLM" & BS & arExpSubKeys(intKey) & BS)

 'set up allowed CLSID's & IPS names for each sub-key
 'fixed bug here: needed to use "intKey" instead of "i" as counter
 If InStr(LCase(arExpSubKeys(intKey)),"devicenotificationcallbacks") > 0 Then

  ReDim arAllowedCLSID(0,1)
  arAllowedCLSID(0,0) = "{8E25992B-373E-486E-80E5-BD23AE417E66}"
  arAllowedCLSID(0,1) = "SyncCenter.dll"

 'fixed bug here: needed to use "intKey" instead of "i" as counter
 ElseIf InStr(LCase(arExpSubKeys(intKey)),"sharedtaskscheduler") > 0 Then

  ReDim arAllowedCLSID(2,1)
  arAllowedCLSID(0,0) = "{438755C2-A8BA-11D1-B96B-00A0C90312E1}"
  arAllowedCLSID(0,1) = "browseui.dll"
  arAllowedCLSID(1,0) = "{8C7461EF-2B13-11d2-BE35-3078302C2030}"
  arAllowedCLSID(1,1) = "browseui.dll"
  arAllowedCLSID(2,0) = "{553858A7-4922-4e7e-B1C1-97140C1C16EF}"  'IE 7
  arAllowedCLSID(2,1) = "ieframe.dll"

 'fixed bug here: needed to use "intKey" instead of "i" as counter
 ElseIf InStr(LCase(arExpSubKeys(intKey)),"shellexecutehooks") > 0 Then

  ReDim arAllowedCLSID(0,1)
  arAllowedCLSID(0,0) = "{AEB6717E-7E19-11d0-97EE-00C04FD91972}"
  arAllowedCLSID(0,1) = "shell32.dll"

 End If 'which Explorer sub-key?

 'find all the names in the Explorer key
 oReg.EnumValues HKLM, arExpSubKeys(intKey), arNames, arType

 'enumerate data if present
 If IsArray(arNames) Then

  'for each name
  For Each strName In arNames

   flagTitle = False

   'fixed bug here: needed to use "intKey" instead of "i" as counter
   CLSIDLocTitle HKLM, arExpSubKeys(intKey), strName, strLocTitle

   For ctrCH = intCLL To 1

    flagWOW = False
    If InStr(UCase(arExpSubKeys(intKey)),"WOW") > 0 Then flagWOW = True
    ResolveCLSID strName, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

    If strIPSDLL <> "" Then

     flagFound = False
     strCN = CoName(IDExe(strIPSDLL))

     'for every CLSID
     'see if CLSID, IPS filename are allowed & IPS CoName = "MS" & hive = HKLM
     For j = 0 To UBound(arAllowedCLSID,1)

      If LCase(strName) = LCase(arAllowedCLSID(j,0)) And _
       LCase(Fso.GetFileName(strIPSDLL)) = LCase(arAllowedCLSID(j,1)) And _
       strCN = MS And ctrCH = 1 Then
       flagFound = True : strWarn = "" : Exit For
      End If

     Next  'allowed CLSID & IPS file name

     If Not flagFound Then
      strWarn = IWarn : flagIWarn = True
     End If

     'if IPS not allowed or ShowAll, output name & value
     If Not flagFound Or flagShowAll Then

      'output the title line if not already done
      TitleLineWrite

      If Not flagTitle Then

       oFN.WriteLine vbCRLF & strWarn & strName & " = " & strLocTitle
       flagTitle = True

      End If

      strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
      If flagWOW Then
       strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
      End IF

     'output CLSID title, InProcServer32 DLL & CoName
      oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
       strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
       strIPSDLL & strCN

     End If  'unexpected data or ShowAll?

    End If  'IPS exists?

   Next  'CLSID Hive

  Next  'arNames array member

 Else  'arNames array not returned

  'if ShowAll, output key name
  If flagShowAll Then TitleLineWrite

 End If  'arNames array exists

Next  'Explorer sub-key

'reset flags
flagFound = False

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arAllowedCLSID(0)
ReDim arExpSubKeys(0)

End If  'SecTest?




'#8. HKCU/HKLM/HKLM-WOW... ShellServiceObjectDelayLoad\

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

arKeys = Array("Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad")
intHKE = 3  'HKCU...SW + HKLM...SW = 1 + 2

If intBits = 64 Then

 arKeys = Array("Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" , _
  "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" )

 intHKE = 11  'HKCU...SW + HKLM...SW + HKLM...SW\Wow = 1 + 2 + 8
              'omit HKCU...SW\Wow

End If

'flagMatch = TRUE if SSODL value is allowable

'form array of allowable SSODL values
Dim arSSODL(7,1)  'array of allowable SSODL values

arSSODL(0,0) = "{35cec8a3-2be6-11d2-8773-92e220524153}" : arSSODL(0,1) = "stobject.dll"         'SysTray (W2K/S, WXP)
arSSODL(1,0) = "{7007accf-3202-11d1-aad2-00805fc1270e}" : arSSODL(1,1) = "netshell.dll"         'Network.ConnectionTray (W2K/S)
arSSODL(2,0) = "{7849596a-48ea-486e-8937-a2a3009f31a9}" : arSSODL(2,1) = "shell32.dll"          'PostBootReminder (WXP)
arSSODL(3,0) = "{aaa288ba-9a4c-45b0-95D7-94d524869db5}" : arSSODL(3,1) = "WPDShServiceObj.dll"  'WPDShServiceObj (WXP)
arSSODL(4,0) = "{bcbcd383-3e06-11d3-91a9-00c04f68105c}" : arSSODL(4,1) = "auhook.dll"           'AUHook (WME)
arSSODL(5,0) = "{e57ce738-33e8-4c51-8354-bb4de9d215d1}" : arSSODL(5,1) = "upnpui.dll"           'UPnPMonitor (WXP)

'W9X, NT4/S, WME, W2K/S, WXP, WVA
'orphaned CLSID (no output): WN7, W81, W10
arSSODL(6,0) = "{e6fb5e20-de35-11cf-9c87-00aa005127ed}" : arSSODL(6,1) = "webcheck.dll"         'WebCheck

arSSODL(7,0) = "{fbeb8a05-beee-4442-804e-409d6c4515e9}" : arSSODL(7,1) = "shell32.dll"          'ShellFolder for CD Burning (WXP)

'for every arKey member
For intKey = 0 To UBound(arKeys)

 For i = 0 To 1  'for each hive

  'respect Hive Key Enabler map
  If HKInclude(intHKE,i,intKey) Then

   strSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

   'find all the names in the key
   oReg.EnumValues arHives(i,1), arKeys(intKey), arNames, arType

   'enumerate data if present
   If IsArray(arNames) Then

    'for each text name
    For Each strName In arNames

     flagMatch = False  'SSODL entry is not allowable

     'get the SSODL value = {CLSID}
     On Error Resume Next
      oReg.GetStringValue arHives(i,1),arKeys(intKey),strName,strCLSID
     On Error GoTo 0

     flagTitle = False

     For ctrCH = intCLL To 1

      flagWOW = False
      If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True
      ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

      'if IPS value exists And is not empty
      If strIPSDLL <> "" Then

       strCN = CoName(IDExe(strIPSDLL))
       strDLL = Fso.GetFileName(strIPSDLL)

       'for every arSSODL member for this OS
       For j = 0 To UBound(arSSODL,1)

        'check the CLSID, DLL filename, CoName, CLSID hive
        If LCase(arSSODL(j,0)) = LCase(strCLSID) And _
          LCase(arSSODL(j,1)) = LCase(strDLL) And _
          LCase(strCN) = " [ms]" And _
         ctrCH = 1 Then
         flagMatch = True  'toggle flag if all four criteria satisfied
         Exit For
        End If

       Next  'arSSODL member

       'write the quote-delimited name and value to the file if unallowable
       If Not flagMatch Or flagShowAll Then

        'output title line if not already done
        TitleLineWrite

        If Not flagTitle Then

         'output SSODL value
         oFN.WriteLine vbCRLF & strName & " = " & strCLSID
         flagTitle = True
        End If

        strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
        If flagWOW Then
         strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
        End IF

        oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
         strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
         strIPSDLL & strCN

       End If  'flagMatch Or flagShowAll?

      End If  'IPS exists?

     Next  'CLSID hive

    Next  'SSODL value (strName) in array

    If flagShowAll Then TitleLineWrite  'W98/WMe/NT4

   End If  'arNames array exists

   'if ShowAll, output key name
   If flagShowAll Then TitleLineWrite

  End If  'HKInclude?

 Next  'hive

Next  'arKey

'reset flags
flagMatch = False

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
strLine = ""

End If  'SecTest?




'#9. HKCU/HKLM/HKLM-WOW... Command Processor\AutoRun
'    HKCU... Policies\System\Shell (W2K/WXP/WVa/Wn7 only)
'    HKCU... Windows\load & run
'    HKLM/HKLM-WOW... Windows\AppInit_DLLs
'    HKLM... Windows NT... Aedebug\
'    HKCU/HKLM... Windows NT... Winlogon\Shell
'    HKLM... Windows NT... Winlogon\Userinit, System, Ginadll, Taskman, VmApplet
'    HKLM... Control\ServiceControlManagerExtension (Wn7 only)
'    HKLM... Control\BootVerificationProgram\ImagePath
'    HKLM... Control\Lsa\Authentication Packages
'    HKLM... Control\Lsa\Notification Packages
'    HKLM... Control\Lsa\Security Packages
'    HKLM... Control\SafeBoot\Option\UseAlternateShell
'    HKLM... Control\SafeBoot\AlternateShell
'    HKLM... Control\SecurityProviders\SecurityProviders
'    HKLM... Control\Session Manager\BootExecute
'    HKLM... Control\Session Manager\Execute
'    HKLM... Control\Session Manager\SetupExecute
'    HKLM... Control\Session Manager\WOW\cmdline, wowcmdline

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim strSP  'member of SecurityProviders array

If strOS <> "W98" And strOS <> "WME" Then

 If strOS <> "NT4" Then  'applies to W2K/WXP/WVA/WN7/WN8/W10

  'HKCU\Software\Microsoft\Command Processor\AutoRun
  strKey = "Software\Microsoft\Command Processor"
  strSubTitle = "HKCU\Software\Microsoft\Command Processor\"
  RegDataChk_v2 HKCU, strKey, "AutoRun", "", "", True


  'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
  strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
  strSubTitle = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\"
  RegDataChk_v2 HKCU, strKey, "Shell", "", "", True

 End If  'not NT4?


 If strOS <> "WN7" Then

  'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load & run
  strSubTitle = "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\"
  strKey = "Software\Microsoft\Windows NT\CurrentVersion\Windows"
  RegDataChk_v2 HKCU, strKey, "load", "", "lrp", True
  RegDataChk_v2 HKCU, strKey, "run", "", "lrp", True

  'W10: executable not launched, but Explorer.EXE throws error message
  'with exclamation point and no text

 End If


 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
 strSubTitle = "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"
 strKey = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
 RegDataChk_v2 HKCU, strKey, "Shell", "explorer.exe", "", True


 If strOS <> "NT4" Then  'applies to W2K/WXP/WVA/WN7

  'HKLM\Software\Microsoft\Command Processor\AutoRun
  strSubTitle = SOCA ("HKLM\Software\Microsoft\Command Processor\")
  strKey = "Software\Microsoft\Command Processor"
  RegDataChk_v2 HKLM, strKey, "AutoRun", "", "", True

  If intBits = 64 Then

   'HKLM\Software\Wow6432Node\Microsoft\Command Processor\AutoRun
   strSubTitle = SOCA ("HKLM\Software\Wow6432Node\Microsoft\Command Processor\")
   strKey = "Software\Wow6432Node\Microsoft\Command Processor"
   RegDataChk_v2 HKLM, strKey, "AutoRun", "", "", True

  End If  '64-bit?

 End If


 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug\
 strSubTitle = SOCA ("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\")
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
 RegDataChk_v2 HKLM, strKey, "Debugger", "drwtsn32 -p %ld -e %ld -g", "", True

 'output "Auto" value if "Debugger" not accepted value
 '(triggering output, which resets strSubTitle to blank)

 'fixed bug here: changed expected value from "1" to ""
 'output any Auto value with warning if Debugger value not expected And not ShowAll
 If strSubTitle = "" And Not flagShowAll Then
  RegDataChk_v2 HKLM, strKey, "Auto", "", "", False
 'use "1" as Auto expected value if ShowAll to avoid extraneous warning
 ElseIf flagShowAll Then
  RegDataChk_v2 HKLM, strKey, "Auto", "1", "", False
 End If


 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 strSubTitle = SOCA ("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\")
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
 RegDataChk_v2 HKLM, strKey, "AppInit_DLLs", "", "", True

 If intBits = 64 Then

  strSubTitle = SOCA ("HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\")
  strKey = "SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
  RegDataChk_v2 HKLM, strKey, "AppInit_DLLs", "", "", True

 End If  '64-bit?

 If strOS = "WVA" Or strOS = "WN7" Then

  'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib
  strSubTitle = SOCA ("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\")
  strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
  RegDataChk_v2 HKLM, strKey, "IconServiceLib", "IconCodecService.dll", "", True

 End If  'XP/WVa/Wn7?


 'Winlogon key name/value pairs

 'GinaDLL=MSGina.dll
 strKey = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
 strSubTitle = SOCA("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\")
 RegDataChk_v2 HKLM, strKey, "GinaDLL", "msgina.dll", "", True

 'Shell=Explorer.exe
 RegDataChk_v2 HKLM, strKey, "Shell", "explorer.exe", "", True

 'System=""
 If strOS = "NT4" Then  'if NT4, check for expected value
  RegDataChk_v2 HKLM, strKey, "System", "lsass.exe", "", True
 Else  'if W2K/WXP/WVA/WN7, check for empty string
  RegDataChk_v2 HKLM, strKey, "System", "", "", True
 End If

 'Taskman=""
 RegDataChk_v2 HKLM, strKey, "Taskman", "", "", True


 'Userinit=userinit,nddeagnt.exe/%SystemRoot%\system32\userinit.exe,
 If strOS = "NT4" Then  'Userinit=userinit,nddeagnt.exe
  RegDataChk_v2 HKLM, strKey, "Userinit", "userinit,nddeagnt.exe", "ui", True
 Else  'W2K/WXP/WVA/WN7 Userinit=%SystemRoot%\system32\userinit.exe,
  RegDataChk_v2 HKLM, strKey, "Userinit", LCase(strFPSF) & "\userinit.exe", "ui", True
 End If


 'VmApplet=rundll32 shell32,Control_RunDLL "sysdm.cpl"
 'WN7: VmApplet=SystemPropertiesPerformance.exe /pagefile
 If strOS = "WN7" Then
  RegDataChk_v2 HKLM, strKey, "VmApplet", "SystemPropertiesPerformance.exe /pagefile", "", False
 Else
  RegDataChk_v2 HKLM, strKey, "VmApplet", "rundll32 shell32,Control_RunDLL ""sysdm.cpl""", "", False
 End If


 If strOS = "WN7" Then

  'HKLM\System\CurrentControlSet\Control\ServiceControlManagerExtension
  strKey = "SYSTEM\CurrentControlSet\Control"
  strSubTitle = SYCA("HKLM" & BS & strKey & "\ServiceControlManagerExtension")
  RegDataChk_v2 HKLM, strKey, "ServiceControlManagerExtension", strFPSF & "\scext.dll", "", True

 End IF


 'HKLM\System\CurrentControlSet\Control\BootVerificationProgram\ImagePath
 strKey = "SYSTEM\CurrentControlSet\Control\BootVerificationProgram"
 strSubTitle = SYCA("HKLM" & BS & strKey & BS)
 RegDataChk_v2 HKLM, strKey, "ImagePath", "", "", True


 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages = "msv1_0"
 strKey = "SYSTEM\CurrentControlSet\Control\Lsa"
 strSubTitle = SYCA("HKLM" & BS & strKey & BS)
 RegDataChk_v2 HKLM, strKey, "Authentication Packages", "msv1_0", "", False


 'Lsa\Notification Packages/Security Packages
 Dim arPkgs : arPkgs = Array("Notification Packages","Security Packages")

 For i = 0 To UBound(arPkgs)

  strKey = "System\CurrentControlSet\Control\Lsa"
  strSubTitle = SYCA("HKLM" & BS & strKey & BS)

  'Notification Packages for all OS's
  If InStr(arPkgs(i),"Notification Packages") > 0 Then

   If InStr(strOSLong,"Windows Server 2003") > 0 Then

    ReDim arSP(3)
    arSP(0) = "RASSFM" : arSP(1) = "KDCSVC" : arSP(2) = "WDIGEST"
    arSP(3) = "scecli"

   ElseIf InStr(strOSLong,"Windows 2000 Server") > 0 Then

    ReDim arSP(3)
    arSP(0) = "FPNWCLNT" : arSP(1) = "RASSFM" : arSP(2) = "KDCSVC"
    arSP(3) = "scecli"

   ElseIf InStr(strOSLong,"Windows Server 2008") > 0 Or _
    InStr(strOSLong,"Windows" & Chr(160) & "Server" & Chr(160) & "2008") > 0 Then

    ReDim arSP(1) : arSP(0) = "scecli" : arSP(1) = "rassfm"

   ElseIf strOS = "NT4" Then

    ReDim arSP(0) : arSP(0) = "FPNWCLNT"

   Else  'all other OS's

    ReDim arSP(0) : arSP(0) = "scecli"

   End If  'which OS?

  End If  'Notification Pkgs?

  'Security Packages for all OS's
  If InStr(arPkgs(i),"Security Packages") > 0 Then

   'set the allowed Security Packages array per the OS version
   If strOS = "NT4" Or strOS = "W2K" Or strOS = "WXP" Then
    ReDim arSP(3)
    arSP(0) = "kerberos" : arSP(1) = "msv1_0" : arSP(2) = "schannel"
    arSP(3) = "wdigest"
   ElseIf strOS = "WVA" Or strOS = "WN7" Then
    ReDim arSP(6)
    arSP(0) = "kerberos" : arSP(1) = "msv1_0" : arSP(2) = "schannel"
    arSP(3) = "wdigest"  : arSP(4) = "tspkg"  : arSP(5) = "pku2u"
    arSP(6) = "livessp"
   End If

  End If  'Notification/Security Packages?

  strValue = "" : strValue1 = "" : strOut = ""

  'read the REG_MULTI_SZ value, split into array
  oReg.GetMultiStringValue HKLM,strKey,arPkgs(i),arValues

  'if Packages value found
  If IsArray(arValues) Then

   For Each strValue in arValues

    'append member to string
    strValue1 = strValue1 & strValue & "|"

    flagFound = False

    'check if allowed
    For j = 0 To UBound(arSP)

     If LCase(strValue) = LCase(arSP(j)) Then

      flagFound = True : Exit For

     End If

    Next  'arSP member

    'if not allowed, append to warning string
    If Not flagFound Then

     If strOut = "" Then  'if this is 1st unallowed value
      strOut = IWarn & "(" & Trim(strValue) & CoName(IDExe(strValue))
      flagIWarn = True
     Else  'not the 1st unallowed value
      strOut = strOut & ", " & Trim(strValue) & CoName(IDExe(strValue))
     End If  'strOut empty?

    End If  'flagFound?

   Next  'arValues member

   strValue1 = Left(strValue1,Len(strValue1)-1)  'lop off trailing "|"

   'if non-approved values present, terminate warning message
   If strOut <> "" Then strOut = strOut & ") "

   'if output needed
   If strOut <> "" Or flagShowAll Then

    TitleLineWrite
    oFN.WriteLine strOut & arPkgs(i) & " = " & strValue1

   End If  'output needed?

  Else  'Packages value not found

   If flagShowAll Then

    TitleLineWrite
    oFN.WriteLine arPkgs(i) & " = (value not set)"

   End If  'flagShowAll?

  End If  'IsArray(arValues)?

 Next  'arPkgs member

 'HKLM\System\CurrentControlSet\Control\SafeBoot\Option\UseAlternateShell
 If strOS <> "NT4" Then
  strKey = "SYSTEM\CurrentControlSet\Control\SafeBoot\Option"
  strSubTitle = SYCA("HKLM" & BS & strKey & BS)
  RegDataChk_v2 HKLM, strKey, "UseAlternateShell", "", "", False

  strKey = "SYSTEM\CurrentControlSet\Control\SafeBoot"
  strSubTitle = SYCA("HKLM" & BS & strKey & BS)
  RegDataChk_v2 HKLM, strKey, "AlternateShell", "cmd.exe", "", True
 End If  'not NT4?


 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders
 strKey = "System\CurrentControlSet\Control\SecurityProviders"
 strSubTitle = SYCA("HKLM" & BS & strKey & BS)

 'set the allowed SecurityProviders array per the OS version
 If strOS = "NT4" Or strOS = "W2K" Or strOS = "WXP" Then

  ReDim arSP(3)
  arSP(0) = "msapsspc.dll" : arSP(1) = "schannel.dll" : arSP(2) = "digest.dll" : arSP(3) = "msnsspc.dll"
  If InStr(strOSLong,"Windows 2000 Server") > 0 Then
   ReDim Preserve arSP(4)
   arSP(4) = "pwdssp.dll"
  End If

 ElseIf strOS = "WVA" Or strOS = "WN7" Then

  ReDim arSP(1)
  arSP(0) = "credssp.dll" : arSP(1) = "pwdssp.dll"

 End IF

 strOut = ""

 On Error Resume Next
  intErrNum = oReg.GetStringValue (HKLM,strKey,"SecurityProviders",strValue)
 On Error GoTo 0

 'if value exists (except for W2K!)
 If intErrNum = 0 And strValue <> "" Then

  'split the value into an array using comma delimiters
  arValues = Split(strValue, ",", -1, vbTextCompare)  'vbTextCompare = 1

  'for every member of the value array
  For Each strVal In arValues

   flagFound = False  'assume DLL is not allowed

   strCN = CoName(IDExe(strVal))

   'for every member of the allowed SP array
   For i = 0 To UBound(arSP)

    'if names match And CoName is MS
    If LCase(Trim(arSP(i))) = LCase(Trim(strVal)) And _
     strCN = MS Then
      flagFound = True : Exit For  'toggle flag to allowed for this DLL
    End If

   Next  'SP array member

   'if this DLL not allowed
   If Not flagFound Then

    If strOut = "" Then  'if this is 1st unallowed value
     strOut = IWarn & "(" & DQ & Trim(strVal) & DQ & strCN
     flagIWarn = True
    Else  'not the 1st unallowed value
     strOut = strOut & ", " & DQ & Trim(strVal) & DQ & strCN
    End If

   End If  'DLL allowed?

  Next  'value array member

  'if non-approved values present, terminate warning message
  If strOut <> "" Then strOut = strOut & ") "

  'output if non-empty strOut or ShowAll
  If strOut <> "" Or flagShowAll Then
   TitleLineWrite
   oFN.WriteLine strOut & "SecurityProviders" & " = " & strValue
  End If

 Else  'SecurityProviders value not set

  TitleLineWrite
  oFN.WriteLine "SecurityProviders" & " = (value not set)"

 End If  'SecurityProviders value exists?


 'HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute
 strKey = "System\CurrentControlSet\Control\Session Manager"
 strSubTitle = SYCA("HKLM" & BS & strKey & BS)

 On Error Resume Next
  intErrNum = oReg.GetMultiStringValue (HKLM,strKey,"BootExecute",arNames)
 On Error GoTo 0

 'initialize output strings
 strLine = "" : strCN = "" : flagInfect = False : strWarn = ""

 If intErrNum = 0 Then  'BootExecute value exists

  'alert if autocheck (and, for W2KS, dfsinit) not in every line of multi-string
  For i = 0 To UBound(arNames)

   If InStr(strOSLong,"Windows 2000 Server") = 0 Then

    'if autocheck not in a line, trim, surround in quotes, look for CoName
    If InStr(LCase(arNames(i)),"autocheck") = 0 Then
     strWarn = IWarn : flagInfect = True : flagIWarn = True
     strLine = StrOutSep(strLine,Trim(arNames(i)) & CoName(IDExe(arNames(i))),"|")
    Else
     'otherwise, trim and surround in quotes
     strLine = StrOutSep(strLine,Trim(arNames(i)),"|")
    End If

   Else

    'if autocheck|DfsInit not in a line, trim, surround in quotes, look for CoName
    If InStr(LCase(arNames(i)),"autocheck") = 0 And _
     InStr(LCase(arNames(i)),"dfsinit") = 0 Then
     strWarn = IWarn : flagInfect = True : flagIWarn = True
     strLine = StrOutSep(strLine,Trim(arNames(i)) & CoName(IDExe(arNames(i))),"|")
    Else
     'otherwise, trim and surround in quotes
     strLine = StrOutSep(strLine,Trim(arNames(i)),"|")
    End If

   End If

  Next  'arNames member

 Else  'BootExecute value doesn't exist or not set

  strLine = "(value not set)"

 End If  'BootExecute value exists?

 'output bootexecute value
 If flagInfect Or flagShowAll Then

  'write name and value to file
  TitleLineWrite

  'output final line
  oFN.WriteLine strWarn & "BootExecute" & " = " & strLine

 End If  'flagInfect Or flagShowAll?


 'HKLM\System\CurrentControlSet\Control\Session Manager\Execute
 strKey = "SYSTEM\CurrentControlSet\Control\Session Manager"
 RegDataChk_v2 HKLM, strKey, "Execute", "", "", False


 'HKLM\System\CurrentControlSet\Control\Session Manager\SetupExecute
 strKey = "SYSTEM\CurrentControlSet\Control\Session Manager"
 RegDataChk_v2 HKLM, strKey, "SetupExecute", "", "", False


 'wowcmdline used to launch 16-bit Windows apps (tested under W2K)
 'cmdline probably used to launch "16-bit DOS apps" (?)
 'testing requires reboot!
 'HKLM\System\CurrentControlSet\Control\WOW
 'WVa does not contain these values by default
 'WN7 does not use these values if present
 If strOS <> "WVA" And strOS <> "WN7" Then
  strKey = "System\CurrentControlSet\Control\WOW"
  strSubTitle = SYCA("HKLM" & BS & strKey & BS)
  RegDataChk_v2 HKLM, strKey, "cmdline", Wshso.ExpandEnvironmentStrings("%SystemRoot%\system32\ntvdm.exe"), "", True
  RegDataChk_v2 HKLM, strKey, "wowcmdline", _
   Wshso.ExpandEnvironmentStrings("%SystemRoot%\system32\ntvdm.exe -a %SystemRoot%\system32\krnl386"), "", False
 End if  'WVa/Wn7?

End If  'not W98/WMe

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
strLine = "" : strWarn = ""

End If  'SecTest?




'#10. HKLM... Authentication\Credential Provider Filters/Credential Providers/PLAP Providers
     'PLAP Providers (WVa/Wn7 only - Pre-Logon Access Provider, PLAP = Single-Sign-On, SSO)

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

If strOS = "WVA" Or strOS = "WN7" Then

 Dim arAuthSubKeys(2)
 arAuthSubKeys(0) = "Credential Provider Filters" : arAuthSubKeys(1) = "Credential Providers"
 arAuthSubKeys(2) = "PLAP Providers"

 'indices: CPF/CP/PP, CLSID number, GUID...IPSDLL
 ReDim arAllowedCLSID(3,31,1)
 arAllowedCLSID(0,0,0) = "{DDC0EED2-ADBE-40b6-A217-EDE16A79A0DE}" : arAllowedCLSID(0,0,1) = "authui.dll"
 arAllowedCLSID(0,1,0) = "{f614806b-ce60-40cd-990f-e8e07df79e49}" : arAllowedCLSID(0,1,1) = "authui.dll"
 arAllowedCLSID(0,2,0) = "{DDC0EED2-ADBE-40b6-A217-EDE16A79A0DE}" : arAllowedCLSID(0,2,1) = "credprovs.dll"

 arAllowedCLSID(1,0,0)  = "{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}" : arAllowedCLSID(1,0,1)  = "authui.dll"
 arAllowedCLSID(1,1,0)  = "{25CBB996-92ED-457e-B28C-4774084BD562}" : arAllowedCLSID(1,1,1)  = "authui.dll"
 arAllowedCLSID(1,2,0)  = "{3dd6bec0-8193-4ffe-ae25-e08e39ea4063}" : arAllowedCLSID(1,2,1)  = "authui.dll"
 arAllowedCLSID(1,3,0)  = "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" : arAllowedCLSID(1,3,1)  = "authui.dll"
 arAllowedCLSID(1,4,0)  = "{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}" : arAllowedCLSID(1,4,1)  = "authui.dll"
 arAllowedCLSID(1,5,0)  = "{cb82ea12-9f71-446d-89e1-8d0924e1256e}" : arAllowedCLSID(1,5,1)  = "authui.dll"
 arAllowedCLSID(1,6,0)  = "{1b283861-754f-4022-ad47-a5eaaa618894}" : arAllowedCLSID(1,6,1)  = "SmartcardCredentialProvider.dll"
 arAllowedCLSID(1,7,0)  = "{8bf9a910-a8ff-457f-999f-a5ca10b4a885}" : arAllowedCLSID(1,7,1)  = "SmartcardCredentialProvider.dll"
 arAllowedCLSID(1,8,0)  = "{8FD7E19C-3BF7-489B-A72C-846AB3678C96}" : arAllowedCLSID(1,8,1)  = "SmartcardCredentialProvider.dll"
 arAllowedCLSID(1,9,0)  = "{94596c7e-3744-41ce-893e-bbf09122f76a}" : arAllowedCLSID(1,9,1)  = "SmartcardCredentialProvider.dll"
 arAllowedCLSID(1,10,0) = "{AC3AC249-E820-4343-A65B-377AC634DC09}" : arAllowedCLSID(1,10,1) = "BioCredProv.dll"
 arAllowedCLSID(1,11,0) = "{BEC09223-B018-416D-A0AC-523971B639F5}" : arAllowedCLSID(1,11,1) = "BioCredProv.dll"
 arAllowedCLSID(1,12,0) = "{e74e57b0-6c6d-44d5-9cda-fb2df5ed7435}" : arAllowedCLSID(1,12,1) = "certCredProvider.dll"
 arAllowedCLSID(1,13,0) = "{600e7adb-da3e-41a4-9225-3c0399e88c0c}" : arAllowedCLSID(1,13,1) = "cngcredui.dll"
 arAllowedCLSID(1,14,0) = "{503739d0-4c5e-4cfd-b3ba-d881334f0df2}" : arAllowedCLSID(1,14,1) = "VaultCredProvider.dll"
 arAllowedCLSID(1,15,0) = "{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}" : arAllowedCLSID(1,15,1) = "wlidcredprov.dll"
 arAllowedCLSID(1,16,0) = "{1ee7337f-85ac-45e2-a23c-37c753209769}" : arAllowedCLSID(1,16,1) = "SmartcardCredentialProvider.dll"
 arAllowedCLSID(1,17,0) = "{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}" : arAllowedCLSID(1,17,1) = "credprovs.dll"
 arAllowedCLSID(1,18,0) = "{25CBB996-92ED-457e-B28C-4774084BD562}" : arAllowedCLSID(1,18,1) = "credprovs.dll"
 arAllowedCLSID(1,19,0) = "{3dd6bec0-8193-4ffe-ae25-e08e39ea4063}" : arAllowedCLSID(1,19,1) = "credprovs.dll"
 arAllowedCLSID(1,20,0) = "{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" : arAllowedCLSID(1,20,1) = "credprovs.dll"
 arAllowedCLSID(1,21,0) = "{cb82ea12-9f71-446d-89e1-8d0924e1256e}" : arAllowedCLSID(1,21,1) = "credprovs.dll"
 arAllowedCLSID(1,22,0) = "{D6886603-9D2F-4EB2-B667-1971041FA96B}" : arAllowedCLSID(1,22,1) = "ngccredprov.dll"
 arAllowedCLSID(1,23,0) = "{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}" : arAllowedCLSID(1,23,1) = "credprovslegacy.dll"
 arAllowedCLSID(1,24,0) = "{2D8B3101-E025-480D-917C-835522C7F628}" : arAllowedCLSID(1,24,1) = "fidocredprov.dll"
 arAllowedCLSID(1,25,0) = "{48B4E58D-2791-456C-9091-D524C6C706F2}" : arAllowedCLSID(1,25,1) = "devicengccredprov.dll"
 arAllowedCLSID(1,26,0) = "{8AF662BF-65A0-4D0A-A540-A338A999D36F}" : arAllowedCLSID(1,26,1) = "FaceCredentialProvider.dll"
 arAllowedCLSID(1,27,0) = "{A910D941-9DA9-4656-8933-AA1EAE01F76E}" : arAllowedCLSID(1,27,1) = "ngccredprov.dll"
 arAllowedCLSID(1,28,0) = "{C885AA15-1764-4293-B82A-0586ADD46B35}" : arAllowedCLSID(1,28,1) = "FaceCredentialProvider.dll"
 arAllowedCLSID(1,29,0) = "{cb82ea12-9f71-446d-89e1-8d0924e1256e}" : arAllowedCLSID(1,29,1) = "credprovslegacy.dll"
 arAllowedCLSID(1,30,0) = "{01A30791-40AE-4653-AB2E-FD210019AE88}" : arAllowedCLSID(1,30,1) = "mgmtrefreshcredprov.dll"
 arAllowedCLSID(1,31,0) = "{27FBDB57-B613-4AF2-9D7E-4FA7A66C21AD}" : arAllowedCLSID(1,31,1) = "TrustedSignalCredProv.dll"

 arAllowedCLSID(2,8,0) = "{5537E283-B1E7-4EF8-9C6E-7AB0AFE5056D}" : arAllowedCLSID(2,8,1) = "rasplap.dll"

 For i = 0 To UBound(arAuthSubKeys)  'for each sub-key

  'assign key & title
  strKey = "Software\Microsoft\Windows\CurrentVersion\Authentication\" & arAuthSubKeys(i)
  strSubTitle = SOCA("HKLM" & BS & strKey & BS)

  'find all the subkeys
  oReg.EnumKey HKLM, strKey, arSubKeys

  'enumerate data if present
  If IsArray(arSubKeys) Then

   'for each subkey
   For Each strSubKey In arSubKeys

    flagTitle = False

    If IsCLSID(strSubKey) Then  'subkey is CPF or CP

     'find the title of the subkey
     CLSIDLocTitle HKLM, strKey & BS & strSubKey, "", strLocTitle

    End If  'subkey is CLSID?

    'for each hive
    For ctrCH = intCLL To 1

     flagMatch = False

     'find CLSID title & IPSDLL
     flagWOW = False
     ResolveCLSID strSubKey, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

     'if IPSDLL not empty
     If strIPSDLL <> "" Then

      strCN = CoName(IDExe(strIPSDLL))

      'see if allowed
      For j = 0 To UBound(arAllowedCLSID,2)

       'toggle match flag if allowed CLSID, allowed IPSDLL, CoName = MS
       If Not flagShowAll And LCase(strSubKey) = LCase(arAllowedCLSID(i,j,0)) And _
        Fso.GetFileName(LCase(strIPSDLL)) = LCase(arAllowedCLSID(i,j,1)) And _
        strCN = MS Then
         flagMatch = True : Exit For
       End If

      Next  'arAllowedCLSID

      'output the title line if not already done
      If flagShowAll Or Not flagMatch Then

       TitleLineWrite

       If Not flagTitle Then

        'error check for W2K if value not set
        oFN.WriteLine vbCRLF & strSubKey & "\(Default) = " & strLocTitle
        flagTitle = True

       End If

       'output CLSID title, InProcServer32 DLL & CoName
       strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
       oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
        strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
        strIPSDLL & strCN

      End If  'flagShowAll or not flagMatch?

     End If  'strIPSDLL exists?

    Next  'CLSID hive

   Next  'Authentication subkey

  End If  'Authentication subkeys exist?

  'if ShowAll, output the key name if not already done
  If flagShowAll Then TitleLineWrite

 Next  'arAuthSubKeys

'recover array memory
ReDim arAllowedCLSID(0,0)

End If  'WVa or Wn7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#11. HKLM... Windows NT... Winlogon\Notify subkey DLLName values

intSection = intSection + 1

If strOS = "NT4" Or strOS = "W2K" Or strOS = "WXP" Then

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

 Set arSK = CreateObject("Scripting.Dictionary")  'key, item

 If strOS = "W2K" Then

  arSK.Add "crypt32chain", "crypt32.dll"
  arSK.Add "cryptnet", "cryptnet.dll"
  arSK.Add "cscdll", "cscdll.dll"
  arSK.Add "sclgntfy", "sclgntfy.dll"
  arSK.Add "senslogn", "wlnotify.dll"
  arSK.Add "termsrv", "wlnotify.dll"
  arSK.Add "wzcnotif", "wzcdlg.dll"

 ElseIf strOS = "WXP" Then

  arSK.Add "crypt32chain", "crypt32.dll"
  arSK.Add "cryptnet", "cryptnet.dll"
  arSK.Add "cscdll", "cscdll.dll"
  arSK.Add "dimsntfy", "dimsntfy.dll"
  arSK.Add "sccertprop", "wlnotify.dll"
  arSK.Add "schedule", "wlnotify.dll"
  arSK.Add "sclgntfy", "sclgntfy.dll"
  arSK.Add "senslogn", "wlnotify.dll"
  arSK.Add "termsrv", "wlnotify.dll"
  arSK.Add "wlballoon", "wlnotify.dll"
  arSK.Add "wgalogon", "wgalogon.dll"

 End If

 arSKk = arSK.Keys : arSKi = arSK.Items

 strKey = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
 strSubTitle = SOCA("HKLM" & BS & strKey & BS)

 'find all the subkeys
 oReg.EnumKey HKLM, strKey, arKeys

 'enumerate data if present
 If IsArray(arKeys) Then

  'for each key
  For Each strSubKey In arKeys

   'initialize variables
   flagInfect = True : strWarn = IWarn

   'get the DLLName data
   On Error Resume Next
    intErrNum = oReg.GetStringValue (HKLM,strKey & BS & strSubKey,"DLLName",strValue)
   On Error GoTo 0

   'if sub-key DLLName name exists And value set (exc for W2K!)
   If intErrNum = 0 And strValue <> "" Then

    strCN = CoName(IDExe(strValue))

    'check dictionary for allowed entry
    For i = 0 To arSK.Count-1

     'if key = dictionary key & value = dictionary item
     If LCase(strSubKey) = arSKk(i) And Fso.GetFileName(LCase(strValue)) = arSKi(i) Then
      'toggle flag & exit -- no output necessary
      flagInfect = False : strWarn = "" : Exit For
     End If

    Next  'dictionary key

    'if DLL not allowed, toggle IWarn flag
    If flagInfect Then flagIWarn = True

    'if flag not found in OS-specific dictionary or ShowAll
    If flagInfect Or flagShowAll Then

     'output title lines if not already done
     TitleLineWrite

     'write the key, name and value to a file
     oFN.WriteLine strWarn & strSubKey & "\DllName = " &_
      strValue & strCN

    End If  'flag not found in dictionary or ShowAll?

   End If  'value missing?

  Next  'Notify subkey

 Else  'Notify subkeys don't exist

  'output title line
  If flagShowAll Then TitleLineWrite

 End If  'Notify subkeys exist?

End If  'NT4/W2K/WXP?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
strWarn = "" : strCN = ""

'recover array memory
arSK.RemoveAll : Set arSK=Nothing

End If  'SecTest?




'#12. HKLM... Windows NT... Winlogon\GPExtensions subkey GUIDs

intSection = intSection + 1

'applies to W2K/WXP/WVA/WN7/WN8/W10
If strOS <> "W98" And strOS <> "WME" And strOS <> "NT4" Then

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

 arKeys = Array("Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions")

 If intBits = 64 Then

  arKeys = Array("Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", _
   "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions")

 End If

 ReDim arAllowedCLSID(60,1)

 'WXP
 arAllowedCLSID(0,0)  = "{0ACDD40C-75AC-47ab-BAA0-BF6DE7E7FE63}" : arAllowedCLSID(0,1)  = "gptext.dll"
 arAllowedCLSID(1,0)  = "{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" : arAllowedCLSID(1,1)  = "gptext.dll"
 arAllowedCLSID(2,0)  = "{C631DF4C-088F-4156-B058-4375F0853CD8}" : arAllowedCLSID(2,1)  = "cscui.dll"
 arAllowedCLSID(3,0)  = "{e437bc1c-aa7d-11d2-a382-00c04f991e27}" : arAllowedCLSID(3,1)  = "gptext.dll"

 'WVA
 arAllowedCLSID(4,0)  = "{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}" : arAllowedCLSID(4,1)  = "iedkcs32.dll"
 arAllowedCLSID(5,0)  = "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}" : arAllowedCLSID(5,1)  = "scecli.dll"

 'WN7
 arAllowedCLSID(6,0)  = "{0ACDD40C-75AC-47ab-BAA0-BF6DE7E7FE63}" : arAllowedCLSID(6,1)  = "wlgpclnt.dll"
 arAllowedCLSID(7,0)  = "{0E28E245-9368-4853-AD84-6DA3BA35BB75}" : arAllowedCLSID(7,1)  = "gpprefcl.dll"
 arAllowedCLSID(8,0)  = "{17D89FEC-5C44-4972-B12D-241CAEF74509}" : arAllowedCLSID(8,1)  = "gpprefcl.dll"
 arAllowedCLSID(9,0)  = "{1A6364EB-776B-4120-ADE1-B63A406A76B5}" : arAllowedCLSID(9,1)  = "gpprefcl.dll"
 arAllowedCLSID(10,0) = "{25537BA6-77A8-11D2-9B6C-0000F8080861}" : arAllowedCLSID(10,1) = "fdeploy.dll"
 arAllowedCLSID(11,0) = "{3610eda5-77ef-11d2-8dc5-00c04fa31a66}" : arAllowedCLSID(11,1) = "dskquota.dll"
 arAllowedCLSID(12,0) = "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}" : arAllowedCLSID(12,1) = "gpprefcl.dll"
 arAllowedCLSID(13,0) = "{426031c0-0b47-4852-b0ca-ac3d37bfcb39}" : arAllowedCLSID(13,1) = "gptext.dll"
 arAllowedCLSID(14,0) = "{42B5FAAE-6536-11d2-AE5A-0000F87571E3}" : arAllowedCLSID(14,1) = "gpscript.dll"
 arAllowedCLSID(15,0) = "{4bcd6cde-777b-48b6-9804-43568e23545d}" : arAllowedCLSID(15,1) = "TsUsbRedirectionGroupPolicyExtension.dll"
 arAllowedCLSID(16,0) = "{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}" : arAllowedCLSID(16,1) = "iedkcs32.dll"
 arAllowedCLSID(17,0) = "{5794DAFD-BE60-433f-88A2-1A31939AC01F}" : arAllowedCLSID(17,1) = "gpprefcl.dll"
 arAllowedCLSID(18,0) = "{6232C319-91AC-4931-9385-E70C2B099F0E}" : arAllowedCLSID(18,1) = "gpprefcl.dll"
 arAllowedCLSID(19,0) = "{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}" : arAllowedCLSID(19,1) = "gpprefcl.dll"
 arAllowedCLSID(20,0) = "{6cfb9c5c-138e-4bb3-8a3d-d5383e910e57}" : arAllowedCLSID(20,1) = "RdpGroupPolicyExtension.dll"
 arAllowedCLSID(21,0) = "{7150F9BF-48AD-4da4-A49C-29EF4A8369BA}" : arAllowedCLSID(21,1) = "gpprefcl.dll"
 arAllowedCLSID(22,0) = "{728EE579-943C-4519-9EF7-AB56765798ED}" : arAllowedCLSID(22,1) = "gpprefcl.dll"
 arAllowedCLSID(23,0) = "{74EE6C03-5363-4554-B161-627540339CAB}" : arAllowedCLSID(23,1) = "gpprefcl.dll"
 arAllowedCLSID(24,0) = "{7933F41E-56F8-41d6-A31C-4148A711EE93}" : arAllowedCLSID(24,1) = "srchadmin.dll"
 arAllowedCLSID(25,0) = "{7B849a69-220F-451E-B3FE-2CB811AF94AE}" : arAllowedCLSID(25,1) = "iedkcs32.dll"
 arAllowedCLSID(26,0) = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" : arAllowedCLSID(26,1) = "scecli.dll"
 arAllowedCLSID(27,0) = "{8A28E2C5-8D06-49A4-A08C-632DAA493E17}" : arAllowedCLSID(27,1) = "gpprnext.dll"
 arAllowedCLSID(28,0) = "{91FBB303-0CD5-4055-BF42-E512A681B325}" : arAllowedCLSID(28,1) = "gpprefcl.dll"
 arAllowedCLSID(29,0) = "{A3F3E39B-5D83-4940-B954-28315B82F0A8}" : arAllowedCLSID(29,1) = "gpprefcl.dll"
 arAllowedCLSID(30,0) = "{AADCED64-746C-4633-A97C-D61349046527}" : arAllowedCLSID(30,1) = "gpprefcl.dll"
 arAllowedCLSID(31,0) = "{B087BE9D-ED37-454f-AF9C-04291E351182}" : arAllowedCLSID(31,1) = "gpprefcl.dll"
 arAllowedCLSID(32,0) = "{B587E2B1-4D59-4e7e-AED9-22B9DF11D053}" : arAllowedCLSID(32,1) = "dot3gpclnt.dll"
 arAllowedCLSID(33,0) = "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}" : arAllowedCLSID(33,1) = "gpprefcl.dll"
 arAllowedCLSID(34,0) = "{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}" : arAllowedCLSID(34,1) = "gpprefcl.dll"
 arAllowedCLSID(35,0) = "{C631DF4C-088F-4156-B058-4375F0853CD8}" : arAllowedCLSID(35,1) = "cscobj.dll"
 arAllowedCLSID(36,0) = "{c6dc5466-785a-11d2-84d0-00c04fb169f7}" : arAllowedCLSID(36,1) = "appmgmts.dll"
 arAllowedCLSID(37,0) = "{cdeafc3d-948d-49dd-ab12-e578ba4af7aa}" : arAllowedCLSID(37,1) = "gptext.dll"
 arAllowedCLSID(38,0) = "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}" : arAllowedCLSID(38,1) = "iedkcs32.dll"
 arAllowedCLSID(39,0) = "{e437bc1c-aa7d-11d2-a382-00c04f991e27}" : arAllowedCLSID(39,1) = "polstore.dll"
 arAllowedCLSID(40,0) = "{E47248BA-94CC-49c4-BBB5-9EB7F05183D0}" : arAllowedCLSID(40,1) = "gpprefcl.dll"
 arAllowedCLSID(41,0) = "{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}" : arAllowedCLSID(41,1) = "gpprefcl.dll"
 arAllowedCLSID(42,0) = "{E5094040-C46C-4115-B030-04FB2E545B00}" : arAllowedCLSID(42,1) = "gpprefcl.dll"
 arAllowedCLSID(43,0) = "{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}" : arAllowedCLSID(43,1) = "gpprefcl.dll"
 arAllowedCLSID(44,0) = "{f3ccc681-b74c-4060-9f26-cd84525dca2a}" : arAllowedCLSID(44,1) = "auditcse.dll"
 arAllowedCLSID(45,0) = "{F9C77450-3A41-477E-9310-9ACD617BD9E3}" : arAllowedCLSID(45,1) = "gpprefcl.dll"
 arAllowedCLSID(46,0) = "{FB2CA36D-0B40-4307-821B-A13B252DE56C}" : arAllowedCLSID(46,1) = "gptext.dll"
 arAllowedCLSID(47,0) = "{fbf687e6-f063-4d9f-9f4f-fd9a26acdd5f}" : arAllowedCLSID(47,1) = "gptext.dll"

 'W10
 arAllowedCLSID(48,0) = "{16be69fa-4209-4250-88cb-716cf41954e0}" : arAllowedCLSID(48,1) = "auditcse.dll"
 arAllowedCLSID(49,0) = "{4D2F9B6F-1E52-4711-A382-6A8B1A003DE6}" : arAllowedCLSID(49,1) = "tsworkspace.dll"
 arAllowedCLSID(50,0) = "{4d968b55-cac2-4ff5-983f-0a54603781a3}" : arAllowedCLSID(50,1) = "WorkFoldersGPExt.dll"
 arAllowedCLSID(51,0) = "{BA649533-0AAC-4E04-B9BC-4DBAE0325B12}" : arAllowedCLSID(51,1) = "pwlauncher.dll"
 arAllowedCLSID(52,0) = "{C34B2751-1CF4-44F5-9262-C3FC39666591}" : arAllowedCLSID(52,1) = "pwlauncher.dll"
 arAllowedCLSID(53,0) = "{169EBF44-942F-4C43-87CE-13C93996EBBE}" : arAllowedCLSID(53,1) = "AppManagementConfiguration.dll"
 arAllowedCLSID(54,0) = "{2A8FDC61-2347-4C87-92F6-B05EB91A201A}" : arAllowedCLSID(54,1) = "gpprefcl.dll"
 arAllowedCLSID(55,0) = "{2BFCC077-22D2-48DE-BDE1-2F618D9B476D}" : arAllowedCLSID(55,1) = "AppManagementConfiguration.dll"
 arAllowedCLSID(56,0) = "{4B7C3B0F-E993-4E06-A241-3FBE06943684}" : arAllowedCLSID(56,1) = "gpprefcl.dll"
 arAllowedCLSID(57,0) = "{7909AD9E-09EE-4247-BAB9-7029D5F0A278}" : arAllowedCLSID(57,1) = "dmenrollengine.dll"
 arAllowedCLSID(58,0) = "{9650FDBC-053A-4715-AD14-FC2DC65E8330}" : arAllowedCLSID(58,1) = "hvsigpext.dll"
 arAllowedCLSID(59,0) = "{F312195E-3D9D-447A-A3F5-08DFFA24735E}" : arAllowedCLSID(59,1) = "dggpext.dll"
 arAllowedCLSID(60,0) = "{FC491EF1-C4AA-4CE1-B329-414B101DB823}" : arAllowedCLSID(60,1) = "dggpext.dll"

 'arAllowedCLSID(61,0) = "" : arAllowedCLSID(61,1) = ""


 For intKey = 0 To UBound(arKeys)

  strSubTitle = SOCA("HKLM" & BS & arKeys(intKey) & BS)

  'find all the subkeys
  oReg.EnumKey HKLM, arKeys(intKey), arSubKeys

  'enumerate data if present
  If IsArray(arSubKeys) Then

   'for each key
   For Each strCLSID In arSubKeys

    flagMatch = False

    'retrieve DLL filename
    On Error Resume Next
     intErrNum = oReg.GetStringValue (HKLM,arKeys(intKey) & BS & strCLSID,"DllName",strDLL)
    On Error GoTo 0

    If intErrNum = 0 Then

     'find CN
     strCN = CoName(IDExe(strDLL))

     'check for allowed GUID
     For i = 0 To UBound(arAllowedCLSID,1)

      'toggle match flag if allowed CLSID, allowed IPSDLL, CoName = MS
      If Not flagShowAll And LCase(strCLSID) = LCase(arAllowedCLSID(i,0)) And _
       Fso.GetFileName(LCase(strDLL)) = LCase(arAllowedCLSID(i,1)) And _
       strCN = MS Then
        flagMatch = True : Exit For
      End If

     Next  'arAllowedCLSID member

     If Not flagMatch Or flagShowAll Then

      'output title line if not already done
      TitleLineWrite

      'output subkey, DLL filename, CN
      oFN.WriteLine strCLSID & "\DllName = " & strDLL & strCN

     End If  'not flagMatch Or ShowAll?

    End If  'DllName retrieved?

   Next  'arSubKeys member (GUID)

  Else  'no subkey array

   'if ShowAll, output the key name if not already done
   If flagShowAll Then TitleLineWrite

  End If  'GPExtensions subkeys exist?

 Next  'arKeys member

 ReDim arAllowedCLSID(0,0)

End If  'W2K/WXP/WVA/WN7-8-10

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#13. HKLM/HKLM-WOW... Windows NT... Image File Execution Options ("Debugger" values)

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'ignore W98/WMe
If strOS <> "W98" And strOS <> "WME" Then

 arKeys = Array("Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")

 If intBits = 64 Then

  arKeys = Array("Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" , _
   "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" )

 End If  'intBits?

 'for every key
 For intKey = 0 To UBound(arKeys)

  strSubTitle = SOCA("HKLM\" & arKeys(intKey) & BS)

  'get executable name sub-keys
  oReg.EnumKey HKLM,arKeys(intKey),arSubKeys

  If IsArray(arSubKeys) Then

   'for each sub-key
   For Each strSubKey in arSubKeys

    strWarn = ""

    'look for Debugger value
    On Error Resume Next
     intErrNum = oReg.GetStringValue (HKLM,arKeys(intKey) & BS & strSubKey,"Debugger",strValue)
    On Error GoTo 0

    'if Debugger value exists
    If intErrNum = 0 And strValue <> "" Then

     'test for single allowed key name & value data
     'skip CoName -- ntsd only added by debugging tools

     'skip allowed sub-key unless ShowAll
     If LCase(strSubKey) = LCase("Your Image File Name Here without a path") And _
      LCase(Trim(strValue)) = "ntsd -d" Then

      If flagShowAll Then

       'output title line if not already done
       TitleLineWrite

       'output sub-key, Debugger value
       oFN.WriteLine strSubKey & "\Debugger = " & strValue

      End If  'flagShowAll?

     Else

      strWarn = IWarn : flagIWarn = True

      'output title line if not already done
      TitleLineWrite

      'output sub-key, warning, Debugger value
      oFN.WriteLine strWarn & strSubKey & "\Debugger = " &_
       strValue & CoName(IDExe(strValue))

     End If  'allowed subkey & value data?

    End If  'strValue MT?

   Next  'IFEO sub-key

  Else  'IFEO sub-key array doesn't exist

   'output title line
   If flagShowAll Then TitleLineWrite

  End If  'IFEO sub-key array exists?

 Next  'arKeys member

End If  'Not W98/WME?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#14. HKCU/HKLM... Policies... Startup/Shutdown, Logon/Logoff scripts (W2K/WXP/WVa/Wn7)

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

strCmd = ""  'script command line string
Dim arScrName(1,1)
arScrName(0,0) = "Logon" : arScrName(0,1) = "Logoff"
arScrName(1,0) = "Startup" : arScrName(1,1) = "Shutdown"

'treat WVa & Wn7 analogously to WXP
Dim strOSCat : strOSCat = strOS
If strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then strOSCat = "WXPVAW7"

Select Case strOSCat

 Case "W2K"

 'collection flag
 Dim flagColl : flagColl = False

  'for HKCU, then HKLM
  For i = 0 To 1

   strKey = "Software\Policies\Microsoft\Windows\System\Scripts"
   strSubTitle = SOCA(arHives(i,0) & BS & strKey & BS)

   'for every script type for the hive
   For j = 0 To 1

    On Error Resume Next
     intErrNum = oReg.GetStringValue(arHives(i,1), strKey, arScrName(i,j), strValue)
    On Error GoTo 0

    If intErrNum = 0 And strValue <> "" Then

     'if value points to SCRIPTS.INI, parse the file
     If Fso.FileExists(strValue & "\scripts.ini") Then

      ScrIFP strValue, arScrName(i,j)

     'value is not empty, so output a warning, or value is not set
     ElseIf strValue <> "" Then

      TitleLineWrite
      oFN.WriteLine "WARNING! Either " & DQ & strValue &_
       "\scripts.ini" & DQ & vbCRLF & Space(9) & "doesn't " &_
       "exist or there " & "is insufficient permission to " &_
       "read it!"

     End If  'value points to SCRIPTS.INI or is not empty

    End If  'HKCU logon/logoff Or HKLM startup/shutdown value exists?

   Next  'name in Scripts key

  'if ShowAll, output title line
  If flagShowAll Then TitleLineWrite

  Next  'hive type

 Case "WXPVAW7"

  'Base Key string
  Dim strBK : strBK = "Software\Policies\Microsoft\Windows\System\Scripts\"
  'modify script location for WVa/Wn7
  If strOS = "WVA" Or strOS = "WN7" Then strBK = "Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\"

  Dim arNKSE  'Numbered (master) Keys containing Script Executable values
  'values: DisplayName, FileSysPath, Script, Parameter
  Dim strSPXP, strDispName, strFSP, strScript, strParam

  'for every hive
  For i = 0 To 1

   'for every script type
   For j = 0 To 1

    strSubTitle = SOCA(arHives(i,0) & BS & strBK & arScrName(i,j) & BS)

    'look for script type subkeys
    oReg.EnumKey arHives(i,1),strBK & arScrName(i,j),arKeys

    'enumerate data if present
    If IsArray(arKeys) Then

     'for each numbered key header (containing numbered script keys)
     For Each strKey in arKeys

      strSubTitle = SOCA(arHives(i,0) & BS & strBK & arScrName(i,j) &_
       BS & strKey & BS)

      'find DisplayName & FileSysPath
      On Error Resume Next
       intErrNum1 = oReg.GetStringValue (arHives(i,1),strBK & arScrName(i,j) &_
        BS & strKey,"DisplayName",strDispName)
      On Error GoTo 0

      'embed existing, non-empty value in quotes
      If intErrNum1 = 0 And strDispName <> "" Then
       strDispName = strDispName
      'for missing or empty value
      Else
       strDispName = "(value not set)"
      End If  'DisplayName exists?

      On Error Resume Next
       intErrNum2 = oReg.GetStringValue (arHives(i,1),strBK & arScrName(i,j) &_
        BS & strKey,"FileSysPath",strFSP)
      On Error GoTo 0

      'if FileSysPath value exists And not empty
      If intErrNum2 = 0 And strFSP <> "" Then

       'look for numbered script subkeys
       oReg.EnumKey arHives(i,1),strBK & arScrName(i,j) & BS & strKey,arNKSE

       'enumerate data if present
       If IsArray(arNKSE) Then

        'for each numbered script key
        For Each strKey2 in arNKSE

         strSPXP = ""  'empty the script path

         'find Parameter value
         On Error Resume Next
          intErrNum3 = oReg.GetStringValue (arHives(i,1),strBK & arScrName(i,j) &_
           BS & strKey & BS & strKey2,"Parameters",strParam)
         On Error GoTo 0

         'if Parameters name doesn't exist, set value to empty string
         If intErrNum3 <> 0 Then strParam = ""

         'find Script value
         On Error Resume Next
          intErrNum4 = oReg.GetStringValue (arHives(i,1),strBK & arScrName(i,j) &_
           BS & strKey & BS & strKey2,"Script",strScript)
         On Error GoTo 0

         'if Script value exists And not empty
         If intErrNum4 = 0 And strScript <> "" Then

          'form script executable string
          'if script string has no backslash, use
          'FileSysPath\Scripts\[script type]\ to locate executable
          'if executable not found, it will not launch
          If InStr(strScript,BS) = 0 Then _
           strSPXP = strFSP & "\Scripts\" & arScrName(i,j) & BS

          strCmd = strSPXP & strScript

          'if parameter string is not empty, append it
          If Trim(strParam) <> "" Then strScript = strScript & " " & strParam

          'write title lines if necessary for this master key
          TitleLineWrite
          oFN.WriteLine "DisplayName = " & strDispName

          'write script executable
          oFN.WriteLine strKey2 & BS & " -> launches: " & strCmd &_
           CoName(IDExe(strCmd))

         End If  'Script value exists And not empty?

        Next  'numbered script executable key

       End If  'script executable key array exists?

      End If  'FileSysPath exists?

     Next  'master key

    End If  'master key array exists?

    'if ShowAll and no prior output, output key
    If flagShowAll Then TitleLineWrite

   Next  'script type

  Next  'hive type

End Select  'W2K or WXPVAW7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#15. HKCU/HKLM PROTOCOLS\Filter & PROTOCOLS\Handler

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim strSKey  'sub-key

Dim ardKeys(1) : ardKeys(0) = "Filter" : ardKeys(1) = "Handler"

ReDim arFilter(24,2,1)

'10 x 3 Filter array: filter title, CLSID value, CLSID\InProcServer32 default value

arFilter(0,0,0) = "Class Install Handler"
arFilter(0,1,0) = "{32B533BB-EDAE-11d0-BD5A-00AA00B92AF1}"
arFilter(0,2,0) = "urlmon.dll"

arFilter(1,0,0) = "deflate"
arFilter(1,1,0) = "{8f6b0360-b80d-11d0-a9b3-006097942311}"
arFilter(1,2,0) = "urlmon.dll"

arFilter(2,0,0) = "gzip"
arFilter(2,1,0) = "{8f6b0360-b80d-11d0-a9b3-006097942311}"
arFilter(2,2,0) = "urlmon.dll"

arFilter(3,0,0) = "lzdhtml"
arFilter(3,1,0) = "{8f6b0360-b80d-11d0-a9b3-006097942311}"
arFilter(3,2,0) = "urlmon.dll"

arFilter(4,0,0) = "text/webviewhtml"
arFilter(4,1,0) = "{733AC4CB-F1A4-11d0-B951-00A0C90312E1}"
arFilter(4,2,0) = "shell32.dll"

arFilter(5,0,0) = "text/webviewhtml"
arFilter(5,1,0) = "{733AC4CB-F1A4-11d0-B951-00A0C90312E1}"
arFilter(5,2,0) = "shdoc401.dll"

arFilter(6,0,0) = "text/webviewhtml"
arFilter(6,1,0) = "{733AC4CB-F1A4-11d0-B951-00A0C90312E1}"
arFilter(6,2,0) = "shdocvw.dll"

arFilter(7,0,0) = "application/octet-stream"
arFilter(7,1,0) = "{1E66F26B-79EE-11D2-8710-00C04F79ED0D}"
arFilter(7,2,0) = "mscoree.dll"

arFilter(8,0,0) = "application/x-complus"
arFilter(8,1,0) = "{1E66F26B-79EE-11D2-8710-00C04F79ED0D}"
arFilter(8,2,0) = "mscoree.dll"

arFilter(9,0,0) = "application/x-msdownload"
arFilter(9,1,0) = "{1E66F26B-79EE-11D2-8710-00C04F79ED0D}"
arFilter(9,2,0) = "mscoree.dll"


'24 x 3 Handler array: handler title, CLSID value, CLSID\InProcServer32 default value

arFilter(0,0,1) = "about"
arFilter(0,1,1) = "{3050F406-98B5-11CF-BB82-00AA00BDCE0B}"
arFilter(0,2,1) = "mshtml.dll"

arFilter(1,0,1) = "cdl"
arFilter(1,1,1) = "{3dd53d40-7b8b-11D0-b013-00aa0059ce02}"
arFilter(1,2,1) = "urlmon.dll"

arFilter(2,0,1) = "dvd"
arFilter(2,1,1) = "{12D51199-0DB5-46FE-A120-47A3D7D937CC}"
arFilter(2,2,1) = "msvidctl.dll"

arFilter(3,0,1) = "file"
arFilter(3,1,1) = "{79eac9e7-baf9-11ce-8c82-00aa004ba90b}"
arFilter(3,2,1) = "urlmon.dll"

arFilter(4,0,1) = "ftp"
arFilter(4,1,1) = "{79eac9e3-baf9-11ce-8c82-00aa004ba90b}"
arFilter(4,2,1) = "urlmon.dll"

arFilter(5,0,1) = "gopher"
arFilter(5,1,1) = "{79eac9e4-baf9-11ce-8c82-00aa004ba90b}"
arFilter(5,2,1) = "urlmon.dll"

arFilter(6,0,1) = "http"
arFilter(6,1,1) = "{79eac9e2-baf9-11ce-8c82-00aa004ba90b}"
arFilter(6,2,1) = "urlmon.dll"

arFilter(7,0,1) = "https"
arFilter(7,1,1) = "{79eac9e5-baf9-11ce-8c82-00aa004ba90b}"
arFilter(7,2,1) = "urlmon.dll"

arFilter(8,0,1) = "its"
arFilter(8,1,1) = "{9D148291-B9C8-11D0-A4CC-0000F80149F6}"
arFilter(8,2,1) = "itss.dll"

arFilter(9,0,1) = "javascript"
arFilter(9,1,1) = "{3050F3B2-98B5-11CF-BB82-00AA00BDCE0B}"
arFilter(9,2,1) = "mshtml.dll"

arFilter(10,0,1) = "local"
arFilter(10,1,1) = "{79eac9e7-baf9-11ce-8c82-00aa004ba90b}"
arFilter(10,2,1) = "urlmon.dll"

arFilter(11,0,1) = "mailto"
arFilter(11,1,1) = "{3050f3DA-98B5-11CF-BB82-00AA00BDCE0B}"
arFilter(11,2,1) = "mshtml.dll"

arFilter(12,0,1) = "mhtml"
arFilter(12,1,1) = "{05300401-BCBC-11d0-85E3-00C04FD85AB4}"
arFilter(12,2,1) = "inetcomm.dll"

arFilter(13,0,1) = "mk"
arFilter(13,1,1) = "{79eac9e6-baf9-11ce-8c82-00aa004ba90b}"
arFilter(13,2,1) = "urlmon.dll"

arFilter(14,0,1) = "ms-its"
arFilter(14,1,1) = "{9D148291-B9C8-11D0-A4CC-0000F80149F6}"
arFilter(14,2,1) = "itss.dll"

arFilter(15,0,1) = "res"
arFilter(15,1,1) = "{3050F3BC-98B5-11CF-BB82-00AA00BDCE0B}"
arFilter(15,2,1) = "mshtml.dll"

arFilter(16,0,1) = "sysimage"
arFilter(16,1,1) = "{76E67A63-06E9-11D2-A840-006008059382}"
arFilter(16,2,1) = "mshtml.dll"

arFilter(17,0,1) = "tv"
arFilter(17,1,1) = "{CBD30858-AF45-11D2-B6D6-00C04FBBDE6E}"
arFilter(17,2,1) = "msvidctl.dll"

arFilter(18,0,1) = "vbscript"
arFilter(18,1,1) = "{3050F3B2-98B5-11CF-BB82-00AA00BDCE0B}"
arFilter(18,2,1) = "mshtml.dll"

arFilter(19,0,1) = "wia"
arFilter(19,1,1) = "{13F3EA8B-91D7-4F0A-AD76-D2853AC8BECE}"
arFilter(19,2,1) = "wiascr.dll"

arFilter(20,0,1) = "vnd.ms.radio"
arFilter(20,1,1) = "{3DA2AA3B-3D96-11D2-9BD2-204C4F4F5020}"
arFilter(20,2,1) = "msdxm.ocx"

arFilter(21,0,1) = "lid"
arFilter(21,1,1) = "{5C135180-9973-46D9-ABF4-148267CBB8BF}"
arFilter(21,2,1) = "msvidctl.dll"

arFilter(22,0,1) = "ndwiat"
arFilter(22,1,1) = "{13F3EA8B-91D7-4F0A-AD76-D2853AC8BECE}"
arFilter(22,2,1) = "WIASCR.DLL"

arFilter(23,0,1) = "tbauth"
arFilter(23,1,1) = "{14654CA6-5711-491D-B89A-58E571679951}"
arFilter(23,2,1) = "tbauth.dll"

arFilter(24,0,1) = "windows.tbauth"
arFilter(24,1,1) = "{14654CA6-5711-491D-B89A-58E571679951}"
arFilter(24,2,1) = "tbauth.dll"

'for Filter, then Handler
For k = 0 To 1

 strKey = "Software\Classes\PROTOCOLS\" & ardKeys(k)

 'for Classes hives for this OS
 For i = intCLL To 1

  strSubTitle = SOCA(arHives(i,0) & BS & strKey & BS)

  'find all the subkeys
  oReg.EnumKey arHives(i,1), strKey, arKeys

  'enumerate data if present
  If IsArray(arKeys) Then

   'for each sub-key
   For Each strSKey In arKeys

    'set default values:
    'flagMatch = True if filter name, CLSID, InProcServer32 DLL, &
    ' DLL CoName match allowed values
    flagMatch = False

    'get the Filter CLSID value
    On Error Resume Next
     intErrNum1 = oReg.GetStringValue (arHives(i,1),strKey & BS & strSKey, _
      "CLSID",strCLSID)
    On Error GoTo 0

    'if CLSID name exists And value set (exc for W2K!)
    If intErrNum1 = 0 And strCLSID <> "" Then

     flagTitle = False

     'for each CLSID hive
     For ctrCH = intCLL To 1

      'retrieve CLSID title & IPSDLL
      flagWOW = False
      ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

      'if IPSDLL retrieved
      If strIPSDLL <> "" Then

       strCN = CoName(IDExe(strIPSDLL))  'find CoName for matching

       'check array for allowed entry
       For j = 0 To UBound(arFilter,1)

        'if filter name, CLSID value, DLL match arFilter & CoName = MS & hive = HKLM
        If LCase(strSKey) = LCase(arFilter(j,0,k)) And _
         LCase(strCLSID) = LCase(arFilter(j,1,k)) And _
         LCase(IDExe(strIPSDLL)) = LCase(strFPSF & BS & arFilter(j,2,k)) And _
         strCN = MS And ctrCH = 1 Then

         'toggle flag, empty warning string
         flagMatch = True : strWarn = "" : Exit For

        End If  'filter name & CLSID match arFilter?

       Next  'arFilter member

       If Not flagMatch Then
        strWarn = IWarn : flagIWarn = True
       End If

       'if Filter/Handler not in allowed array Or ShowAll
       If Not flagMatch Or flagShowAll Then

        TitleLineWrite

        If Not flagTitle Then
         'write the Filter/Handler name and CLSID value
         oFN.WriteLine vbCRLF & strWarn & strSKey & "\CLSID = " & strCLSID
        End If

        strCTHL = LIP & "CLSID} = " : intCTHLS = intCS

        oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
         strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
         strIPSDLL & strCN

       End If  'Not flagMatch Or ShowAll?

      End If  'strIPSDLL exists?

     Next  'CLSID hive

    ElseIf flagShowAll Then  'strCLSID doesn't exist & flagShowAll

     oFN.WriteLine vbCRLF & strSKey & "\CLSID = (value not set)"

    End If  'strCLSID exists?

   Next  'Filter subkey

   If flagShowAll Then TitleLineWrite  'W98/WMe/NT4

  Else  'Filter subkeys not an array

   If flagShowAll Then TitleLineWrite

  End If  'Filter subkeys exist?

 Next  'PROTOCOLS/Filter hive

Next  'Filter then Handler

'reset flag
flagMatch = False

'reset strings
strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
strWarn = ""

'recover array memory
ReDim arFilter(0)

End If  'SecTest?




'#16. Context menu shell extensions

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim arClasses(4)
arClasses(0) = "*" : arClasses(1) = "AllFilesystemObjects" : arClasses(2) = "Directory"
arClasses(3) = "Directory\Background" : arClasses(4) = "Folder"

Dim arHandlers()
ReDim arHandlers(4)
arHandlers(0) = "ColumnHandlers"   : arHandlers(1) = "ContextMenuHandlers"
arHandlers(2) = "CopyHookHandlers" : arHandlers(3) = "DragDropHandlers"
arHandlers(4) = "PropertySheetHandlers"

Dim arSWC(1)  'SoftWare\Classes
arSWC(0) = "Software\Classes\" : arSWC(1) = "Software\Classes\Wow6432Node\"

'permits search for 32-bit & 64-bit CLSIDs for 64-bit shell extensions
Dim flagWOWCLSID

Dim intSWCUL : intSWCUL = 0  'SoftWare\Classes Upper Limit

'for each Class name
For Each strClass In arClasses

 If strClass = "Folder" Then
  ReDim Preserve arHandlers(5)
  arHandlers(5) = "ExtShellFolderViews"
 End If

 'for each shellex handler at that class
 For Each strHandler In arHandlers

  If LCase(strHandler) = "columnhandlers" Then

   ReDim arAllowedDlls(2)

   'ColumnHandlers
   arAllowedDlls(0)  = "docprop2.dll" : arAllowedDlls(1) = "faxshell.dll"
   arAllowedDlls(2)  = "shell32.dll"

  ElseIf LCase(strHandler) = "contextmenuhandlers" Then

   ReDim arAllowedDlls(14)

   'ContextMenuHandlers
   arAllowedDlls(0)  = "cscui.dll"    : arAllowedDlls(1) = "msshrui.dll"
   arAllowedDlls(2)  = "ntshrui.dll"  : arAllowedDlls(3) = "runext.dll"
   arAllowedDlls(4)  = "sbdrop.dll"   : arAllowedDlls(5) = "shcompui.dll"
   arAllowedDlls(6)  = "shdoc401.dll" : arAllowedDlls(7) = "shell32.dll"
   arAllowedDlls(8)  = "syncui.dll"   : arAllowedDlls(9) = "twext.dll"
   arAllowedDlls(10)  = "workfoldersshell.dll" : arAllowedDlls(11) = "FileSyncShell64.dll"
   arAllowedDlls(12)  = "FileSyncShell.dll" : arAllowedDlls(13)  = "shellext.dll"
   arAllowedDlls(14)  = "appresolver.dll"

   'layout.dll, CoName = "Microsoft"

  ElseIf LCase(strHandler) = "copyhookhandlers" Then

   ReDim arAllowedDlls(5)

   'CopyHookHandlers
   arAllowedDlls(0) = "mydocs.dll"   : arAllowedDlls(1) = "ntshrui.dll"
   arAllowedDlls(2) = "shdocvw.dll"  : arAllowedDlls(3) = "shell32.dll"
   arAllowedDlls(4) = "w3ext.dll"    : arAllowedDlls(5) = "msshrui.dll"

  ElseIf LCase(strHandler) = "dragdrophandlers" Then

   ReDim arAllowedDlls(0)

   'DragDropHandlers
   arAllowedDlls(0)  = "zipfldr.dll"

  ElseIf LCase(strHandler) = "propertysheethandlers" Then

   ReDim arAllowedDlls(13)

   'PropertySheetHandlers
   arAllowedDlls(0)  = "cryptext.dll" : arAllowedDlls(1) = "cscui.dll"
   arAllowedDlls(2)  = "dfsshlex.dll" : arAllowedDlls(3) = "docprop.dll"
   arAllowedDlls(4)  = "docprop2.dll" : arAllowedDlls(5) = "mydocs.dll"
   arAllowedDlls(6)  = "ntshrui.dll"  : arAllowedDlls(7) = "rshx32.dll"
   arAllowedDlls(8)  = "shell32.dll"  : arAllowedDlls(9) = "syncui.dll"
   arAllowedDlls(10) = "twext.dll"    : arAllowedDlls(11) = "w3ext.dll"
   arAllowedDlls(12) = "msshrui.dll"  : arAllowedDlls(13) = "srmshell.dll"

  End If


  'for each hive
  For i = intCLL To 1

   intSWCUL = 0

   'search Wow if 64-bit & HKLM
   If (intBits = 64) And (i = 1) Then intSWCUL = 1

   For j = 0 To intSWCUL

    strSubTitle = SOCA(arHives(i,0) & BS & arSWC(j) & strClass &_
     "\shellex\" & strHandler & BS)
    strKey = arSWC(j) & strClass & "\shellex\" & strHandler

    'look for handler sub-keys
    oReg.EnumKey arHives(i,1),strKey,arSubKeys

    'if subkeys exist
    If IsArray(arSubKeys) Then

     'for each sub-key
     For Each strSubKey In arSubKeys

      'check default value if CLSID
      On Error Resume Next
       intErrNum2 = oReg.GetStringValue(arHives(i,1),strKey & BS & strSubKey,"",strCLSID)
      On Error GoTo 0

      'if default value is CLSID
      If intErrNum2 = 0 And IsCLSID(strCLSID) Then

       flagTitle = False

       'for each hive
       For ctrCH = intCLL To 1

        'toggles flagWOW in ResolveCLSID call
        For flagWOWCLSID = 0 To 1

         'find CLSID title and IPSDLL
         ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOWCLSID

         'if IPSDLL not empty
         If strIPSDLL <> "" Then

          'assume not allowed
          flagAllow = False

          'check if allowed
          For Each strAllowedDlls In arAllowedDlls

           'find CoName
           strCN = CoName(IDExe(strIPSDLL))

           'fixed bug here: removed requirement for HKLM
           'if allowed and CoName = MS, toggle allowed flag
           If LCase(Trim(Fso.GetFileName(strIPSDLL))) = LCase(strAllowedDlls) And _
            strCN = MS Then
            flagAllow = True : Exit For
           End If

          Next  'arAllowedDlls element

          'output if not allowed or ShowAll
          If Not flagAllow Or flagShowAll Then

           TitleLineWrite

           'output handler name & CLSID if not already done
           If Not flagTitle Then
            oFN.WriteLine vbCRLF & strSubKey & "\(Default) = " & strCLSID
            flagTitle = True
           End If

           strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
           If flagWOWCLSID Then
            strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
           End If

           'output CLSID, IPSDLL & CoName
           oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
            strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
            strIPSDLL & strCN

          End If  'not allowed Or ShowAll?

         End If  'strIPSDLL exists?

        Next 'flagWOWCLSID

       Next  'CLSID hive

      ElseIf IsCLSID(strSubKey) Then  'sub-key may be CLSID

       flagTitle = False

       'for each hive
       For ctrCH = intCLL To 1

        'toggles flagWOW in ResolveCLSID call
        For flagWOWCLSID = 0 To 1

         'find sub-key title
         CLSIDLocTitle arHives(ctrCH,1), strKey & BS & strSubKey, "", strLocTitle

         'find CLSID title and IPSDLL
         ResolveCLSID strSubKey, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOWCLSID

         'if IPSDLL not empty
         If strIPSDLL <> "" Then

          flagAllow = False

          'check if allowed
          For Each strAllowedDlls In arAllowedDlls

           'find CoName
           strCN = CoName(IDExe(strIPSDLL))

           'if allowed and CoName = MS, toggle allowed flag
           If LCase(Trim(Fso.GetFileName(strIPSDLL))) = LCase(strAllowedDlls) And _
            strCN = MS And ctrCH = 1 Then
            flagAllow = True : Exit For
           End If

          Next  'arAllowedDlls element

          'output if not allowed or ShowAll
          If Not flagAllow Or flagShowAll Then

           TitleLineWrite

           'output handler name & CLSID if not already done
           If Not flagTitle Then
            oFN.WriteLine vbCRLF & strSubKey & "\(Default) = " & strLocTitle
            flagTitle = True
           End If

           strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
           If flagWOWCLSID Then
            strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
           End If

           'output CLSID, IPSDLL & CoName
           oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
            strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
            strIPSDLL & strCN

          End If  'not allowed Or ShowAll?

         End If  'strIPSDLL not empty?

        Next  'flagWOWCLSID

       Next  'CLSID hive

      End If  'default value CLSID?

     Next  'sub-key

     If flagShowAll Then TitleLineWrite  'W98/WMe/NT4

    End If  'sub-keys exist?

    If flagShowAll Then TitleLineWrite

   Next  'Classes stub

  Next  'hive

 Next  'arHandler

Next  'class

'reset strings
strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#17. HKCU/HKLM executable file type (bat/cmd/com/exe/hta/pif/scr)

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'this section does *not* always know what executes -- it looks
'for everything in the OS-specific executable filetype chain

'WVa 64-bits reflects all entries made to HKCU\Software\Classes in HKCU\Software\Classes\Wow6432Node
'                                         does not appear to use HKCU\Software\Wow6432Node\Classes
'                                         HKLM\Software\Classes in HKLM\Software\Classes\Wow6432Node
'                                         HKLM\Software\Classes\Wow6432Node in HKLM\Software\Wow6432Node\Classes

'Key Default Values, ProgidDV array is a sub argument that is not otherwise used
Dim arKeyDV(), arProgidDV()

'set up executables/executable file type/expected value arrays, counter
Public arExeExt, arExeFT, arExpVal

'Classes parent key array
Dim arCL : arCL = Array("Software\Classes\")

'for 64-bit OS, add Wow6432Node branches to Classes parent key array
If intBits = 64 Then
 arCL = Array("Software\Classes\","Software\Wow6432Node\Classes\","Software\Classes\Wow6432Node\")
End If  '64-bit?

'executable extensions/file types/expected values arrays
If strOS = "W98" Or strOS = "WME" Then

 arExeExt = Array(".bat",".com",".exe",".hta",".pif",".scr")
 arExeFT = Array("batfile","comfile","exefile","htafile","piffile","scrfile")
 arExpVal = Array("""%1"" %*","""%1"" %*","""%1"" %*", _
  LCase(Fso.GetSpecialFolder(1)) & "\mshta.exe ""%1"" %*", _
  """%1"" %*","""%1"" /s")

Else

 arExeExt = Array(".bat",".cmd",".com",".exe",".hta",".pif",".scr")
 arExeFT = Array("batfile","cmdfile","comfile","exefile","htafile","piffile","scrfile")
 arExpVal = Array("""%1"" %*","""%1"" %*","""%1"" %*","""%1"" %*", _
  LCase(Fso.GetSpecialFolder(1)) & "\mshta.exe ""%1"" %*", _
  """%1"" %*","""%1"" /s")

 'modify htafile for 64-bit OS/Wn8
 If intBits = 64 Then

  arExpVal = Array("""%1"" %*","""%1"" %*","""%1"" %*","""%1"" %*", _
   LCase(Wshso.ExpandEnvironmentStrings("%WINDIR%")) & "\syswow64\mshta.exe ""%1"" %*", _
   """%1"" %*","""%1"" /s")

  If strOSSS = "WN8" Or strOSSS = "W10" Then

   arExpVal = Array("""%1"" %*","""%1"" %*","""%1"" %*","""%1"" %*", _
    LCase(Wshso.ExpandEnvironmentStrings("%WINDIR%")) & "\syswow64\mshta.exe ""%1"" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%U{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} %*", _
    """%1"" %*","""%1"" /s")

  End If  'Wn8?

 End If  '64-bit?

End If  'W9x?

strTitle = "Default executables:"

'progid's are examined by extension


'main Classes\...\.ext loop

'1st pass -- Classes\...\.ext loop

'for each ext
For i = 0 To UBound(arExeExt)

 strOut = "" : ReDim arKeyDV(0) : strSubTitle = arExeExt(i)

 'for each hive
 'arHives(0,0) = "HKCU" : arHives(1,0) = "HKLM"
 'arHives(0,1) = &H80000001 : arHives(1,1) = &H80000002
 'based on DEFETester results, exclude HKCU for W9x/WME/NT4
 'WME uses HKCU...Explorer\FileExts
 For k = intCLL to 1

  'for each Classes key
  For j = 0 To UBound(arCL)

   'set up key\.ext to test; arCL has trailing BS
   strKey = arCL(j) & arExeExt(i)

   'initial pass -- look for .EXT/CurVer default value
   CLAnal i, k, strKey, arKeyDV

  Next  'hive

 Next  'Classes branch

 'sort, then un-dupe Progid array arKeyDV
 SortArray arKeyDV : UnDupeArray arKeyDV


'2nd pass -- Classes\...\Progid loop

  'for each hive
 'exclude HKCU for W9x/WME/NT4, but WME uses HKCU...Explorer\FileExts
 For k = intCLL to 1

  'for each Classes key
  For j = 0 To UBound(arCL)

   'for every progid found for the extension
   For ii = 0 To UBound(arKeyDV)

    'perform 2nd pass iff progid not MT
    If arKeyDV(ii) <> "" Then

     'set up key\progid to test; arCL has trailing BS
     strKey = arCL(j) & arKeyDV(ii)

     'second pass -- look for .EXT/CurVer default value
     CLAnal i, k, strKey, arProgidDV

    End If  'progid MT?

   Next  'arKeyDV member

  Next  'Classes branch

 Next  'hive

 If flagShowAll Or strOut <> "" Then
  TitleLineWrite : oFN.WriteLine strOut
 End If


 'FileExts loop

 'WME/W2K/WXP/WVA/WN7 only
 If strOS <> "W98" And strOS <> "NT4" Then

  'suffix to FileExts .ext key where FileExt .ext name found
  Dim strFileExtNLocn : strFileExtNLocn = ""
  If strOS = "WVA" Or strOS = "WN7" Then strFileExtNLocn = "\UserChoice"

  'dictionary of FileExt .ext names (Progid/Application) and values (class locations)
  Dim dictFileExtNV : Set dictFileExtNV = CreateObject("Scripting.Dictionary")

  'populate OS-dependent dictionary
  If strOS = "WME" Or strOS = "W2K" Then

   dictFileExtNV.Add "Application","Applications\"

  ElseIf strOs = "WXP" Then

   dictFileExtNV.Add "Progid",""
   dictFileExtNV.Add "Application","Applications\"

  ElseIf strOs = "WVA" Or strOS = "WN7" Then

   dictFileExtNV.Add "Progid",""

  End if  'OS?

  'array of FileExt .ext names = dictionary keys
  Dim arFileExtN : arFileExtN = dictFileExtNV.Keys

  Dim flagWN8Hash : flagWN8Hash = True  'False if OS=Wn8 & Hash name/value pair not found

  strSubTitle = "FileExts\" & arExeExt(i)
  strOut = ""

  'check if the FileExts\.ext\ key exists

  'ex for WXP : Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\
  'ex for WVa+: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\UserChoice\
  strKey = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" & arExeExt(i)

  intErrNum0 = oReg.EnumValues (HKCU,strKey,arProgidDV)

  'if the key exists
  If intErrNum0 = 0 Then

   'reset the key variable to include \UserChoice\ for certain OS's
   'ex: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\Progid
   'ex: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\UserChoice\Progid

   strKey = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" &_
    arExeExt(i) & strFileExtNLocn

   'for each FileExt\.ext name/value pair
   For j = 0 To UBound(arFileExtN)

    'look for corresponding FileExts .ext name's value
    'ex for WXP : Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\Progid=bixfile
    'ex for WVa+: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\UserChoice\Progid=bixfile (or, for Wn8, long string)

    intErrNum1 = oReg.GetStringValue (HKCU,strKey,arFileExtN(j),strValue)

    If intErrNum1 = 0 And strValue <> "" Then

     'for Wn8, check for required "Hash" value
     If strOSSS = "WN8" Then

      flagWN8Hash = False  'toggle flag
      intErrNum2 = oReg.GetStringValue (HKCU,strKey,"Hash",strHashValue)

      If intErrNum2 = 0 And strHashValue <> "" Then

       flagWn8Hash = True
       strOut = "HKCU\" & strKey & BS & "Hash = " & strHashValue

       TitleLineWrite : oFN.WriteLine strOut : strOut = ""

      End If  'strHashValue not MT?

     End If  'Wn8?

     If flagWN8Hash Then  'True except in WN8 with missing Hash name/value pair

       'form output string
      strOut = "HKCU\" & strKey & BS & arFileExtN(j) & " = " & strValue

      TitleLineWrite : oFN.WriteLine strOut : strOut = ""

      'for each hive
      'exclude HKCU for W9x/NT4/WMe
      For k = intCLL to 1

       'look in every Classes branch
       For ii = 0 To UBound(arCL)

        'look for App/ProgID value in Classes or in Classes\Applications in each hive
        'WME does not use HKCU...Classes\Applications, but look there anyway
        CLAnal i, k, arCL(ii) & dictFileExtNV.Item(arFileExtN(j)) & strValue, arKeyDV

        'if App/ProgID name is "Application" And value (may be) filename,
        'add ".exe" to value and try to find it again
        If strOut = "" And dictFileExtNV.Item(arFileExtN(j)) = "Application" Then

         CLAnal i, k, arCL(ii) & dictFileExtNV.Item(arFileExtN(j)) & strValue & ".exe", arKeyDV

        End If  'strOut empty & value (may be) filename?

        'output if found
        If strOut <> "" Then
         TitleLineWrite : oFN.WriteLine strOut : strOut = ""
        End If

       Next  'Classes branch

      Next  'hive

     End If  'flagWN8Hash?

    Else  'FileExt App/ProgID value not found

     'if ShowAll, output FileExts key if not already done
     If flagShowAll Then
      strOut = "HKCU\" & strKey & BS & arFileExtN(j) & " = (value not set)"
      TitleLineWrite : oFN.WriteLine strOut
     End If

    End If  'FileExts App/ProgID value found?

   Next  'possible FileExt ext name (App/ProgID)

  Else

   'if ShowAll, output FileExts key if not already done
   If flagShowAll Then
    strOut = "HKCU\" & strKey & BS & " = (key not found)"
    TitleLineWrite : oFN.WriteLine strOut
   End If

  End If  'FileExts .ext key found?

 End If  'not W98/NT4?

 'if ShowAll, output FileExts key if not already done
 If flagShowAll Then TitleLineWrite

Next  '.ext

'clean up
strTitle = "" : strSubTitle = "" : strOut = ""

End If  'SecTest?







'#18. System/Group Policies

' Checked Keys:
'
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Assocations
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments
' HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl
' HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Download
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Main
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Security
' HKCU/HKLM\Software\Policies\Microsoft\Internet Explorer\Toolbar
' HKCU\Software\Policies\Microsoft\MMC\{0E752416-F29E-4195-A9DD-7F0D4D5A9D71}
' HKCU\Software\Policies\Microsoft\MMC\{0F3621F1-23C6-11D1-AD97-00AA00B88E5A}
' HKCU\Software\Policies\Microsoft\MMC\{394C052E-B830-11D0-9A86-00C04FD8DBF7}
' HKCU\Software\Policies\Microsoft\MMC\{0F6B957D-509E-11D1-A7CC-0000F87571E3}
' HKCU\Software\Policies\Microsoft\MMC\{58221C66-EA27-11CF-ADCF-00AA00A80033}
' HKCU\Software\Policies\Microsoft\MMC\{0F6B957E-509E-11D1-A7CC-0000F87571E3}
' HKCU\Software\Policies\Microsoft\MMC\{58221C67-EA27-11CF-ADCF-00AA00A80033}
' HKCU\Software\Policies\Microsoft\MMC\{5D6179C8-17EC-11D1-9AA9-00C04FD8FE93}
' HKCU\Software\Policies\Microsoft\MMC\{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}
' HKCU\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}
' HKCU\Software\Policies\Microsoft\MMC\{84DE202D-5D95-4764-9014-A46F994CE856}
' HKCU\Software\Policies\Microsoft\MMC\{84DE202E-5D95-4764-9014-A46F994CE856}
' HKCU\Software\Policies\Microsoft\MMC\{975797FC-4E2A-11D0-B702-00C04FD8DBF7}
' HKCU\Software\Policies\Microsoft\MMC\{FC715823-C5FB-11D1-9EEF-00A0C90347FF}
' HKCU\Software\Policies\Microsoft\MMC\{D02B1F72-3407-48ae-BA88-E8213C6761F1}
' HKCU\Software\Policies\Microsoft\MMC\{D02B1F73-3407-48ae-BA88-E8213C6761F1}
' HKCU\Software\Policies\Microsoft\MMC\FX:{b05566ac-fe9c-4368-be02-7a4cbb7cbe11}
' HKCU\Software\Policies\Microsoft\MMC\FX:{b05566ad-fe9c-4363-be05-7a4cbb7cb510}
' HKCU\Software\Policies\Microsoft\MMC\FX:{b05566ae-fe9c-4363-be05-7a4cbb7cb510}
' HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3
' HKCU/HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4
' HKCU\Software\Policies\Microsoft\Windows\Network Connections
' HKCU\Software\Policies\Microsoft\Windows\System
' HKCU\Software\Policies\Microsoft\Windows\Task Scheduler5.0
' HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate
' HKLM\Software\Policies\Microsoft\Windows\Windows Defender
' HKLM\Software\Policies\Microsoft\Windows\Windows Defender\Real-time Protection
' HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting
' HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Const ATPL = "Administrative Templates|"
Const WSSSLP = "Windows Settings|Security Settings|Local Policies|"
Const WC = "Windows Components|"
 Const IEX = "Internet Explorer|"
 Const MMC = "Microsoft Management Console|"
 Const WEX = "Windows Explorer|"
Const SMTB = "Start Menu and Taskbar|"
Const DT = "Desktop|"
 Const DAD = "Desktop / Active Desktop|"
Const CP = "Control Panel|"
Const NWK = "Network|"
Const SYS = "System|"

'assign System or Group Policy name
Dim strPolName : strPolName = "Group "
If strOS = "W98" Or strOS = "WME" Or strOS = "NT4" Then strPolName = "System "

'arRecNames() contains GPO names that are RECognized by SR
'the values do not represent a security risk

'arAllowedNames() contains GPO name/value pairs that are allowed
'differing values would pose a security risk

'arRecNames(#,0-2)
'#,0 = registry name
'#,1 = GPedit branch
'#,2 = GPedit setting

Dim arDisCplNames, strDisCplName, strDisCplValue
'fixed bug here: ReDimGPOArrays run to initialize arAllowedNames
'so GPRecognizer would execute correctly on first use

ReDimGPOArrays

'set title line
strTitle = strPolName & "Policies {policy setting}:"
'add GPEdit location to title if GP used (W2K, WXP, WVa, Wn7)
If flagGP Then strTitle = "Group Policies {GPedit.msc branch and setting}:"
strSubTitle = "Note: detected settings may not have any effect."


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"

ReDim arRecNames(3,2)

arRecNames(0,0) = "NoChangingWallPaper" : arRecNames(0,1) = ATPL & CP & "Display|"
arRecNames(0,2) = "Disable changing wallpaper}"
If strOS = "WXP" Or strOS = "WVA" Then arRecNames(0,2) = "Prevent changing wallpaper}"

arRecNames(1,0) = "NoClosingComponents" : arRecNames(1,1) = ATPL & DT & DAD
If strOS = "WN7" Then arRecNames(1,1) = ATPL & DT & DT
arRecNames(1,2) = "Prohibit closing items}"

arRecNames(2,0) = "NoDeletingComponents" : arRecNames(2,1) = ATPL & DT & DAD
If strOS = "WN7" Then arRecNames(2,1) = ATPL & DT & DT
arRecNames(2,2) = "Prohibit deleting items}"

arRecNames(3,0) = "NoEditingComponents" : arRecNames(3,1) = ATPL & DT & DAD
If strOS = "WN7" Then arRecNames(3,1) = ATPL & DT & DT
arRecNames(3,2) = "Prohibit editing items}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Associations"

ReDim arRecNames(0,2)

arRecNames(0,0) = "DefaultFileTypeRisk"
arRecNames(0,1) = ATPL & WC & "Attachment Manager|"
arRecNames(0,2) = "Default risk level for file attachments}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"

ReDim arRecNames(1,2)

arRecNames(0,0) = "ScanWithAntiVirus"
arRecNames(0,1) = ATPL & WC & "Attachment Manager|"
arRecNames(0,2) = "Notify antivirus programs when opening attachments}"

arRecNames(1,0) = "SaveZoneInformation"
arRecNames(1,1) = ATPL & WC & "Attachment Manager|"
'avoids the need to unblock downloaded files
arRecNames(1,2) = "Do not preserve zone information in file attachments}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

ReDim arRecNames(31,3)

arRecNames(0,0) = "ClassicShell" : arRecNames(0,1) = ATPL & WC & WEX
arRecNames(0,2) = "Enable Classic Shell / Turn on Classic Shell}"

arRecNames(1,0) = "ForceActiveDesktopOn"
arRecNames(1,1) = ATPL & DT & DAD : arRecNames(1,2) = "Enable Active Desktop}"
If strOS = "W98" Or strOS = "NT4" Then
 arRecNames(1,1) = "" : arRecNames(1,2) = "unrecognized setting}"
End If

arRecNames(2,0) = "NoActiveDesktop" : arRecNames(2,1) = ATPL & DT & DAD
arRecNames(2,2) = "Disable Active Desktop}"

arRecNames(3,0) = "NoActiveDesktopChanges" : arRecNames(3,1) = ATPL & DT & DAD
arRecNames(3,2) = "Prohibit changes [and freeze position of desktop icons]}"

'added by GP, but ignored in practice, presence of DisallowCpl subkey name/value pairs
'sufficient to hide applets, even if this DWORD = 0 or absent
arRecNames(4,0) = "DisallowCpl" : arRecNames(4,1) = ATPL & CP
arRecNames(4,2) = "Hide specified control panel applets / items}"

arRecNames(5,0) = "NoToolbarCustomize" : arRecNames(5,1) = ATPL & WC & IEX & "Toolbars|"
arRecNames(5,2) = "Disable customizing browser toolbar buttons}"

arRecNames(6,0) = "NoBandCustomize" : arRecNames(6,1) = ATPL & WC & IEX & "Toolbars|"
arRecNames(6,2) = "Disable customizing browser toolbars}"

arRecNames(7,0) = "NoFolderOptions" : arRecNames(7,1) = ATPL & WC & WEX
arRecNames(7,2) = "Removes the Folder Options menu item from the Tools menu}"

arRecNames(8,0) = "NoWindowsUpdate" : arRecNames(8,1) = ATPL & SMTB
arRecNames(8,2) = "Remove links and access to Windows Update}"

arRecNames(9,0) = "NoTrayItemsDisplay" : arRecNames(9,1) = ATPL & SMTB
arRecNames(9,2) = "Hide the notification area}"

arRecNames(10,0) = "NoSetTaskbar" : arRecNames(10,1) = ATPL & SMTB
arRecNames(10,2) = "Prevent changes to Taskbar and Start Menu Settings}"

arRecNames(11,0) = "TaskbarLockAll" : arRecNames(11,1) = ATPL & SMTB
arRecNames(11,2) = "Lock all taskbar settings}"

arRecNames(12,0) = "TaskbarNoAddRemoveToolbar" : arRecNames(12,1) = ATPL & SMTB
arRecNames(12,2) = "Prevent users from adding or removing toolbars}"

arRecNames(13,0) = "TaskbarNoDragToolbar" : arRecNames(13,1) = ATPL & SMTB
arRecNames(13,2) = "Prevent users from rearranging toolbars}"

arRecNames(14,0) = "NoStartMenuMorePrograms" : arRecNames(14,1) = ATPL & SMTB
arRecNames(14,2) = "Remove All Programs list from the Start menu}"

arRecNames(15,0) = "NoSMHelp" : arRecNames(15,1) = ATPL & SMTB
arRecNames(15,2) = "Remove Help menu from Start Menu}"

arRecNames(16,0) = "NoAutoUpdate" : arRecNames(16,1) = ATPL & SYS
arRecNames(16,2) = "Windows Automatic Updates}"

arRecNames(17,0) = "NoSecurityTab" : arRecNames(17,1) = ATPL & WC & WEX
arRecNames(17,2) = "Remove Security tab}"

arRecNames(18,0) = "NoSaveSettings" : arRecNames(18,1) = ATPL & DT
arRecNames(18,2) = "Don't save settings at exit}"

arRecNames(19,0) = "NoStartBanner" : arRecNames(19,1) = ""
arRecNames(19,2) = "Remove " & DQ & "Click here to begin" & DQ & " from Start button}"

arRecNames(20,0) = "NoFavoritesMenu" : arRecNames(20,1) = ATPL & SMTB
arRecNames(20,2) = "Remove Favorites menu from Start Menu}"

arRecNames(21,0) = "NoWinKeys" : arRecNames(21,1) = ""
arRecNames(21,2) = "Disable Windows+X hotkeys}"

arRecNames(22,0) = "NoSMMyDocs" : arRecNames(22,1) = ATPL & SMTB
arRecNames(22,2) = "Remove Documents menu from Start Menu}"

arRecNames(23,0) = "NoSMMyPictures" : arRecNames(23,1) = ATPL & SMTB
arRecNames(23,2) = "Remove My Pictures icon from Start Menu}"

arRecNames(24,0) = "NoNetworkConnections" : arRecNames(24,1) = ATPL & SMTB
arRecNames(24,2) = "Remove Network & Dial-up Connections from Start Menu}"
If strOS = "WXP" Then arRecNames(24,2) = "Remove Network Connections from Start Menu}"

arRecNames(25,0) = "NoSharedDocuments" : arRecNames(25,1) = ATPL & WC & WEX
arRecNames(25,2) = "Remove Shared Documents from My Computer}"

arRecNames(26,0) = "NoLogoff" : arRecNames(26,1) = ATPL & SYS & "Logon/Logoff|"
arRecNames(26,2) = "Disable Logoff}"

arRecNames(27,0) = "NoInternetIcon" : arRecNames(27,1) =  ATPL & DT
arRecNames(27,2) = "Hide Internet Explorer icon on desktop}"

arRecNames(28,0) = "NoSearchFilesInStartMenu" : arRecNames(28,1) = ATPL & SMTB
arRecNames(28,2) = "Do not search for files}"

arRecNames(29,0) = "NoTrayItemsDisplay" : arRecNames(29,1) = ATPL & SMTB
arRecNames(29,2) = "Hide the notification area}"

arRecNames(30,0) = "NoClose" : arRecNames(30,1) = ATPL & SMTB
arRecNames(30,2) = "Remove and prevent access to the Shut Down, Restart, Sleep, and Hibernate commands}"

arRecNames(31,0) = "NoRun" : arRecNames(31,1) = ATPL & SMTB
arRecNames(31,2) = "Remove Run menu from Start Menu}"


ReDim arAllowedNames(4,3)

arAllowedNames(0,0) = "NoDriveTypeAutoRun" : arAllowedNames(0,1) = ATPL & WC & "AutoPlay Policies|"
arAllowedNames(0,2) = "Turn off Autoplay}"
arAllowedNames(0,3) = "***"

arAllowedNames(1,0) = "NoDriveAutoRun" : arAllowedNames(1,1) = ""
arAllowedNames(1,2) = "Turn off autoplay for drive letter}"
arAllowedNames(1,3) = "***"

arAllowedNames(2,0) = "MaxRecentDocs" : arAllowedNames(2,1) = ATPL & WC & WEX
arAllowedNames(2,2) = "Maximum number of recent documents}"
arAllowedNames(2,3) = "***"

arAllowedNames(3,0) = "HonorAutoRunSetting" : arAllowedNames(3,1) = "{not in GPedit.msc|"
arAllowedNames(3,2) = "Per MSKB 967715, enable Autorun settings in Hotfixes 950582, 967715, and 953252}"
arAllowedNames(3,3) = "1"

arAllowedNames(4,0) = "NoCDBurning" : arAllowedNames(4,1) =  ATPL & WC & WEX
arAllowedNames(4,2) = "Remove CD Burning features}"
arAllowedNames(4,3) = "0"

GPRecognizer HKCU, strKey : ReDimGPOArrays


ReDim arAllowedNames(9,3)

arAllowedNames(0,0) = "NoDriveTypeAutoRun" : arAllowedNames(0,1) = ATPL & WC & "AutoPlay Policies|"
arAllowedNames(0,2) = "Turn off Autoplay}"
arAllowedNames(0,3) = "***"

arAllowedNames(1,0) = "NoDriveAutoRun" : arAllowedNames(1,1) = ""
arAllowedNames(1,2) = "Turn off autoplay for drive letter}"
arAllowedNames(1,3) = "***"

arAllowedNames(2,0) = "HonorAutoRunSetting" : arAllowedNames(2,1) = "{not in GPedit.msc|"
arAllowedNames(2,2) = "Per MSKB 967715, enable Autorun settings in Hotfixes 950582, 967715, and 953252}"
arAllowedNames(2,3) = "1"

arAllowedNames(3,0) = "NoCDBurning" : arAllowedNames(3,1) =  ATPL & WC & WEX
arAllowedNames(3,2) = "Remove CD Burning features}"
arAllowedNames(3,3) = "0"

arAllowedNames(4,0) = "ShowSuperHidden" : arAllowedNames(4,1) = "{not in GPedit.msc|"
arAllowedNames(4,2) = "Displays protected operating system files}"
arAllowedNames(4,3) = "1"

If intBits = 64 Then
 arAllowedNames(5,0) = "ForceActiveDesktopOn"
 arAllowedNames(5,1) = "{not in GPedit.msc under Computer Configuration|"
 arAllowedNames(5,2) = "Enable Active Desktop and prevent users from disabling it}"
 arAllowedNames(5,3) = "0"

 arAllowedNames(6,0) = "NoActiveDesktop"
 arAllowedNames(6,1) = "{not in GPedit.msc under Computer Configuration|"
 arAllowedNames(6,2) = "Disable Active Desktop and prevent users from enabling it}"
 arAllowedNames(6,3) = "1"

 arAllowedNames(7,0) = "NoActiveDesktopChanges"
 arAllowedNames(7,1) = "{not in GPedit.msc under Computer Configuration|"
 arAllowedNames(7,2) = "Prevent enabling or disabling Active Desktop or changing its configuration}"
 arAllowedNames(7,3) = "1"
End If

If strOS = "WVA" Then
 arAllowedNames(8,0) = "BindDirectlyToPropertySetStorage"
 arAllowedNames(8,1) = "{not in GPedit.msc|"
 arAllowedNames(8,2) = "Per MSKB 947265, enable indexing of document custom properties " &_
  "after install of optional hotfix}"
 arAllowedNames(8,3) = "***"
End If

If strOSSS = "W10" Then
 arAllowedNames(9,0) = "NoRecentDocsHistory"
 arAllowedNames(9,1) = "{not in GPedit.msc|"
 arAllowedNames(9,2) = "HKCU value of " & DQ & "0" & DQ & " prevents creation of shortcuts for recently opened documents}"
 arAllowedNames(9,3) = "0"
End If

GPRecognizer HKLM, strKey : ReDimGPOArrays


'omitted Control Panel applets
strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\System"

ReDim arRecNames(6,2)

arRecNames(0,0) = "DisableRegistryTools" : arRecNames(0,1) = ATPL & SYS
arRecNames(0,2) = "Disable registry editing tools}"
If strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then arRecNames(0,2) = "Prevent access to " &_
 "registry editing tools}"

arRecNames(1,0) = "NoDispBackgroundPage" : arRecNames(1,1) = ATPL & CP & "Display|"
arRecNames(1,2) = "Hide Background tab}"
If strOS = "WXP" Or strOS = "WVA" Then arRecNames(1,2) = "Hide Desktop tab}"

arRecNames(2,0) = "NoDispCpl"
arRecNames(2,1) = ATPL & CP & "Display|"
arRecNames(2,2) = "Disable Display in Control Panel}"
If strOS = "WXP" Or strOS = "WVA" Then arRecNames(2,2) = "Remove Display in Control Panel}"
If strOS = "WN7" Then arRecNames(2,2) = "Disable the Display Control Panel}"

arRecNames(3,0) = "Wallpaper" : arRecNames(3,1) = ATPL & DT & DAD
arRecNames(3,2) = "Active Desktop Wallpaper|Wallpaper Name:}"
If strOS = "WVA" Then arRecNames(3,2) = "Desktop Wallpaper|Wallpaper Name:}"

arRecNames(4,0) = "WallpaperStyle" : arRecNames(4,1) = ATPL & DT & DAD
arRecNames(4,2) = "Active Desktop Wallpaper|Wallpaper Style:}"
If strOS = "WVA" Then arRecNames(4,2) = "Desktop Wallpaper|Wallpaper Style:}"

arRecNames(5,0) = "DisableTaskMgr"
arRecNames(5,1) = ATPL & SYS & "Ctrl+Alt+Del Options|"
If strOS = "W2K" Then arRecNames(5,1) = ATPL & SYS & "Logon/Logoff|"
arRecNames(5,2) = "Remove Task Manager}"

arRecNames(5,0) = "NoDispSettingsPage"
arRecNames(5,1) = ATPL & CP & "Display|"
arRecNames(5,2) = "Hide Settings tab}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall"

ReDim arRecNames(1,2)

arRecNames(0,0) = "NoAddRemovePrograms"
arRecNames(0,1) = ATPL & CP & "Add or Remove Programs|"
arRecNames(0,2) = "Remove Add or Remove Programs}"

arRecNames(1,0) = "NoRemovePage"
arRecNames(1,1) = ATPL & CP & "Add or Remove Programs|"
arRecNames(1,2) = "Hide Change or Remove Programs page}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"

ReDim arRecNames(1,2)

arRecNames(0,0) = "DisableWindowsUpdateAccess"
arRecNames(0,1) = ATPL & WC & "Windows Update|"
arRecNames(0,2) = "Remove access to use all Windows Update features (part 1 of 2)}"

arRecNames(1,0) = "DisableWindowsUpdateAccessMode"
arRecNames(1,1) = ATPL & WC & "Windows Update|"
arRecNames(1,2) = "Remove access to use all Windows Update features (part 2 of 2)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\WindowsUpdate"

ReDim arRecNames(0,2)

arRecNames(0,0) = "DisableWindowsUpdateAccess"
arRecNames(0,1) = ATPL & SYS & "Internet Communication Management|Internet Communication settings|"
arRecNames(0,2) = "Turn off access to all Windows Update features}"

GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Control Panel"

ReDim arRecNames(15,2)

arRecNames(1,0) = "Advanced" : arRecNames(1,1) = ATPL & WC & IEX
arRecNames(1,2) = "Disable changing Advanced page settings}"

arRecNames(2,0) = "AdvancedTab"                                         'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(2,2) = "Disable the Advanced page}"

arRecNames(3,0) = "Connection Settings"                                 'HKLM
arRecNames(3,1) = ATPL & WC & IEX
arRecNames(3,2) = "Disable changing connection settings}"

arRecNames(4,0) = "ConnectionsTab"                                      'HKLM
arRecNames(4,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(4,2) = "Disable the Connections page}"

arRecNames(5,0) = "ContentTab"                                          'HKLM
arRecNames(5,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(5,2) = "Disable the Content page}"

arRecNames(6,0) = "DisableRIED"                                         'HKLM
arRecNames(6,1) = ATPL & WC & IEX & "Internet Control Panel|Advanced Page|"
arRecNames(6,2) = "Do not allow resetting Internet Explorer settings}"

arRecNames(7,0) = "GeneralTab"                                          'HKLM
arRecNames(7,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(7,2) = "Disable the General page}"

arRecNames(8,0) = "HomePage" : arRecNames(8,1) = ATPL & WC & IEX
arRecNames(8,2) = "Disable changing home page settings}"

arRecNames(9,0) = "PrivacyTab"                                          'HKLM
arRecNames(9,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(9,2) = "Disable the Privacy page}"

arRecNames(10,0) = "ProgramsTab"                                        'HKLM
arRecNames(10,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(10,2) = "Disable the Programs page}"

arRecNames(11,0) = "Proxy"                                              'HKLM
arRecNames(11,1) = ATPL & WC & IEX
arRecNames(11,2) = "Disable changing proxy settings}"

arRecNames(12,0) = "ResetWebSettings" : arRecNames(12,1) = ATPL & WC & IEX
arRecNames(12,2) = "Disable the Reset Web Settings feature}"

arRecNames(13,0) = "SecurityTab"                                        'HKLM
arRecNames(13,1) = ATPL & WC & IEX & "Internet Control Panel|"
arRecNames(13,2) = "Disable the Security page}"

arRecNames(14,0) = "Settings" : arRecNames(14,1) = ATPL & WC & IEX      'HKLM
If strOS = "WN7" Then arRecNames(14,1) = arRecNames(14,1) & "Delete Browsing History|"
arRecNames(14,2) = "Prevent the deletion of temporary Internet files and cookies}"

arRecNames(15,0) = "Autoconfig" : arRecNames(15,1) = ATPL & WC & IEX    'HKLM
arRecNames(15,2) = "Disable changing Automatic Configuration settings}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Download"

ReDim arRecNames(1,2)

arRecNames(0,0) = "RunInvalidSignatures"              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Advanced Page|"
arRecNames(0,2) = "Allow software to run or install even if the signature is invalid}"

arRecNames(1,0) = "CheckExeSignatures"                'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Advanced Page|"
arRecNames(1,2) = "Check for signatures on downloaded programs}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions"

ReDim arRecNames(1,2)

arRecNames(0,0) = "NoChangeDefaultSearchProvider"     'HKLM
arRecNames(0,1) = ATPL & WC & IEX
arRecNames(0,2) = "Restrict changing the default search provider}"

arRecNames(1,0) = "NoSearchCustomization"
arRecNames(1,1) = ATPL & WC & IEX
arRecNames(1,2) = "Search: Disable Search Customization}"

ReDim arAllowedNames(0,3)

arAllowedNames(0,0) = "NoSearchBox"
arAllowedNames(0,1) = ATPL & WC & IEX
arAllowedNames(0,2) = "Prevent Internet Explorer Search box from displaying}"
arAllowedNames(0,3) = "***"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Main"

ReDim arRecNames(1,2)

arRecNames(0,0) = "Enable Browser Extensions"         'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Advanced Page|"
arRecNames(0,2) = "Allow third-party browser extensions}"

arRecNames(1,0) = "Start Page"
arRecNames(1,1) = ATPL & WC & IEX
arRecNames(1,2) = "Disable changing home page settings -- Home Page imposed by this setting}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"

ReDim arRecNames(0,2)

arRecNames(0,0) = "*"                                 'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Security Features|Scripted Window Security Restrictions|"
arRecNames(0,2) = "Internet Explorer Processes}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\PhishingFilter"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Enabled"                           'HKLM
arRecNames(0,1) = ATPL & WC & IEX
arRecNames(0,2) = "Turn off Managing Phishing filter}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Privacy"

ReDim arRecNames(0,2)

arRecNames(0,0) = "CleanTIF"                          'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Delete Browsing History|"
arRecNames(0,2) = "Prevent Deleting Temporary Internet Files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Restrictions"

ReDim arRecNames(2,2)

arRecNames(0,0) = "NoExtensionManagement"             'HKLM
arRecNames(0,1) = ATPL & WC & IEX
arRecNames(0,2) = "Do not allow users to enable or disable add-ons}"

arRecNames(1,0) = "NoPopupManagement"                 'HKLM
arRecNames(1,1) = ATPL & WC & IEX
arRecNames(1,2) = "Turn off pop-up management}"

arRecNames(2,0) = "NoBrowserOptions"
arRecNames(2,1) = ATPL & WC & IEX & "Browser Menus|"
arRecNames(2,2) = "Tools menu: Disable Internet Options... menu option}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Security"

ReDim arRecNames(1,2)

arRecNames(0,0) = "DisableFixSecuritySettings"        'HKLM
arRecNames(0,1) = ATPL & WC & IEX
arRecNames(0,2) = "Prevent ""Fix settings"" functionality}"

arRecNames(1,0) = "DisableSecuritySettingsCheck"      'HKLM
arRecNames(1,1) = ATPL & WC & IEX
arRecNames(1,2) = "Turn off the Security Settings Check feature}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Internet Explorer\Toolbar"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Locked"                            'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Toolbars|"
arRecNames(0,2) = "Lock all Toolbars}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{0E752416-F29E-4195-A9DD-7F0D4D5A9D71}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Windows Firewall with Advanced Security}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{0F3621F1-23C6-11D1-AD97-00AA00B88E5A}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Extension snap-ins|"
arRecNames(0,2) = "System Properties}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{0F6B957D-509E-11D1-A7CC-0000F87571E3}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Computers) (part 1 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays



strKey = "Software\Policies\Microsoft\MMC\{0F6B957E-509E-11D1-A7CC-0000F87571E3}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Users) (part 1 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{394C052E-B830-11D0-9A86-00C04FD8DBF7}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Extension snap-ins|"
arRecNames(0,2) = "Event Viewer}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{58221C66-EA27-11CF-ADCF-00AA00A80033}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Services}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{58221C67-EA27-11CF-ADCF-00AA00A80033}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Computer Management}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{5D6179C8-17EC-11D1-9AA9-00C04FD8FE93}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Local Users and Groups}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Security Settings}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{84DE202D-5D95-4764-9014-A46F994CE856}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Computers) (part 2 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{84DE202E-5D95-4764-9014-A46F994CE856}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Users) (part 2 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Group Policy Object Editor}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{975797FC-4E2A-11D0-B702-00C04FD8DBF7}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Event Viewer}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{D02B1F72-3407-48ae-BA88-E8213C6761F1}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Computers) (part 3 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{D02B1F73-3407-48ae-BA88-E8213C6761F1}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Administrative Templates (Users) (part 3 of 3)}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{E12BBB5D-D59D-4E61-947A-301D25AE8C23}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Group Policy Management}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\{FC715823-C5FB-11D1-9EEF-00A0C90347FF}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|Group Policy snap-in extensions|"
arRecNames(0,2) = "Internet Explorer Maintenance}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\FX:{b05566ac-fe9c-4368-be02-7a4cbb7cbe11}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Windows Firewall with Advanced Security}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\FX:{b05566ad-fe9c-4363-be05-7a4cbb7cb510}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Group Policy|"
arRecNames(0,2) = "Event Viewer (Windows Vista}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\MMC\FX:{b05566ae-fe9c-4363-be05-7a4cbb7cb510}"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Restrict_Run"
arRecNames(0,1) = ATPL & WC & MMC & "Restricted/Permitted snap-ins|Extension snap-ins|"
arRecNames(0,2) = "Event Viewer (Windows Vista}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\Control Panel\Desktop"

ReDim arRecNames(0,2)

arRecNames(0,0) = "SCRNSAVE.EXE"
arRecNames(0,1) = ATPL & CP & "Personalization|"
arRecNames(0,2) = "Force specific screen saver}"
If strOS = "W2K" Or strOS = "WXP" Then
 arRecNames(0,1) = ATPL & CP & "Display|"
 arRecNames(0,2) = "Screen Saver executable name}"
End If

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Trusted Sites Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Trusted Sites Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Trusted Sites Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Internet Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Internet Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Internet Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Restricted Sites Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Restricted Sites Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Locked-Down Restricted Sites Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Trusted Sites Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Trusted Sites Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Trusted Sites Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Internet Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Internet Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Internet Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"

ReDim arRecNames(2,2)

arRecNames(0,0) = "1004"                              'HKLM
arRecNames(0,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Restricted Sites Zone|"
arRecNames(0,2) = "Download unsigned ActiveX controls}"

arRecNames(1,0) = "1201"                              'HKLM
arRecNames(1,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Restricted Sites Zone|"
arRecNames(1,2) = "Initialize and script ActiveX controls not marked as safe}"

arRecNames(2,0) = "1806"                              'HKLM
arRecNames(2,1) = ATPL & WC & IEX & "Internet Control Panel|Security Page|Restricted Sites Zone|"
arRecNames(2,2) = "Launching programs and unsafe files}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\Network Connections"

ReDim arRecNames(6,2)

arRecNames(0,0) = "NC_LanProperties"
arRecNames(0,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(0,1) = ATPL & NWK & "Network Connections|"
arRecNames(0,2) = "Prohibit access to properties of a LAN connection}"

arRecNames(1,0) = "NC_LanChangeProperties"
arRecNames(1,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(1,1) = ATPL & NWK & "Network Connections|"
arRecNames(1,2) = "Prohibit access to properties of components of a LAN connection}"

arRecNames(2,0) = "NC_RasChangeProperties"
arRecNames(2,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(2,1) = ATPL & NWK & "Network Connections|"
arRecNames(2,2) = "Prohibit access to properties of components of a remote access connection}"

arRecNames(3,0) = "NC_AddRemoveComponents"
arRecNames(3,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(3,1) = ATPL & NWK & "Network Connections|"
arRecNames(3,2) = "Prohibit adding and removing components for a LAN or remote access connection}"

arRecNames(4,0) = "NC_DeleteConnection"
arRecNames(4,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(4,1) = ATPL & NWK & "Network Connections|"
arRecNames(4,2) = "Prohibit deletion of remote access connections}"

arRecNames(5,0) = "NC_Statistics"
arRecNames(5,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(5,1) = ATPL & NWK & "Network Connections|"
arRecNames(5,2) = "Prohibit viewing of status for an active connection}"

arRecNames(6,0) = "NC_AllowAdvancedTCPIPConfig"
arRecNames(6,1) = ATPL & NWK & "Network and Dial-up Connections|"
If strOS = "WVA" or strOS = "WN7" Then arRecNames(6,1) = ATPL & NWK & "Network Connections|"
arRecNames(6,2) = "Prohibit TCP/IP advanced configuration}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\System"

ReDim arRecNames(0,2)

arRecNames(0,0) = "DisableCMD"
arRecNames(0,1) = ATPL & SYS
arRecNames(0,2) = "Disable the command prompt}"
If strOS = "WVA" Or strOS = "WN7" Then arRecNames(0,2) = "Prevent access to the command prompt}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\Task Scheduler5.0"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Task Deletion"                     'HKLM
arRecNames(0,1) = ATPL & WC & "Task Scheduler|"
arRecNames(0,2) = "Prohibit Task deletion}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows Defender"

ReDim arRecNames(0,2)

arRecNames(0,0) = "DisableAntiSpyware"                'HKLM
arRecNames(0,1) = ATPL & WC & "Windows Defender|"
arRecNames(0,2) = "Turn off Windows Defender}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows Defender\Real-time Protection"

ReDim arRecNames(0,2)

arRecNames(0,0) = "DisableRealtimeMonitoring"         'HKLM
arRecNames(0,1) = ATPL & WC & "Windows Defender|"
arRecNames(0,2) = "Turn off Real-Time Monitoring}"

GPRecognizer HKCU, strKey : GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Policies\Microsoft\Windows\Windows Error Reporting"

ReDim arRecNames(0,2)

arRecNames(0,0) = "Disabled"
arRecNames(0,1) = ATPL & WC & "Windows Error Reporting|"
arRecNames(0,2) = "Disable Windows Error Reporting}"

GPRecognizer HKCU, strKey : ReDimGPOArrays


ReDim arAllowedNames(3,3)

arAllowedNames(0,0) = "Disabled"
arAllowedNames(0,1) = ATPL & WC & "Windows Error Reporting|"
arAllowedNames(0,2) = "Disable Windows Error Reporting}"
arAllowedNames(0,3) = "0"

arAllowedNames(1,0) = "DontSendAdditionalData"
arAllowedNames(1,1) = ATPL & WC & "Windows Error Reporting|"
arAllowedNames(1,2) = "Decline additional data requests from MS " &_
 "in response to a Windows Error Reporting event}"
arAllowedNames(1,3) = "0"

arAllowedNames(2,0) = "BypassPowerThrottling"
arAllowedNames(2,1) = ATPL & WC & "Windows Error Reporting|"
arAllowedNames(2,2) = "Check for solutions and upload report data even if " &_
 "the computer is running on battery power}"
arAllowedNames(2,3) = "1"

arAllowedNames(3,0) = "BypassNetworkCostThrottling"
arAllowedNames(3,1) = ATPL & WC & "Windows Error Reporting|"
arAllowedNames(3,2) = "Transmit data even if network cost is restricted}"
arAllowedNames(3,3) = "1"

GPRecognizer HKLM, strKey : ReDimGPOArrays


strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\System"

ReDim arRecNames(5,2)

arRecNames(0,0) = "EnableFullTrustStartupTasks"
arRecNames(0,1) = "UNDOCUMENTED!|"
arRecNames(0,2) = "Value of " & DQ & "2" & DQ & " present by default in W10 v1709 (Fall Creators Update)}"

arRecNames(1,0) = "EnableUwpStartupTasks"
arRecNames(1,1) = "UNDOCUMENTED!|"
arRecNames(1,2) = "Value of " & DQ & "2" & DQ & " present by default in W10 v1709 (Fall Creators Update)}"

arRecNames(2,0) = "SupportFullTrustStartupTasks"
arRecNames(2,1) = "UNDOCUMENTED!|"
arRecNames(2,2) = "Value of " & DQ & "1" & DQ & " present by default in W10 v1709 (Fall Creators Update)}"

arRecNames(3,0) = "SupportUwpStartupTasks"
arRecNames(3,1) = "UNDOCUMENTED!|"
arRecNames(3,2) = "Value of " & DQ & "1" & DQ & " present by default in W10 v1709 (Fall Creators Update)}"

arRecNames(4,0) = "DSCAutomationHostEnabled"
arRecNames(4,1) = "UNDOCUMENTED!|"
arRecNames(4,2) = "Value of " & DQ & "2" & DQ & " present by default in W10 v1607 (Anniversary Update)}"

arRecNames(5,0) = "EnableCursorSuppression"
arRecNames(5,1) = "UNDOCUMENTED!|"
arRecNames(5,2) = "Value of " & DQ & "1" & DQ & " present by default in W10 v1607 (Anniversary Update)}"


ReDim arAllowedNames(16,3)

arAllowedNames(0,0) = "ConsentPromptBehaviorAdmin" : arAllowedNames(0,1) = WSSSLP & "Security Options|"
arAllowedNames(0,2) = "User Account Control: Behavior Of The Elevation " &_
 "Prompt For Administrators In Admin Approval Mode}"
arAllowedNames(0,3) = "2" : If strOS = "WN7" Then arAllowedNames(0,3) = "5"

arAllowedNames(1,0) = "ConsentPromptBehaviorUser" : arAllowedNames(1,1) = WSSSLP & "Security Options|"
arAllowedNames(1,2) = "User Account Control: Behavior Of The Elevation " &_
 "Prompt For Standard Users}"
arAllowedNames(1,3) = "1" : If strOS = "WN7" Then arAllowedNames(1,3) = "3"

arAllowedNames(2,0) = "dontdisplaylastusername" : arAllowedNames(2,1) = WSSSLP & "Security Options|"
arAllowedNames(2,2) = "Interactive logon: Do not display last user name}" : arAllowedNames(2,3) = "***"

arAllowedNames(3,0) = "EnableInstallerDetection" : arAllowedNames(3,1) = WSSSLP & "Security Options|"
arAllowedNames(3,2) = "User Account Control: Detect Application " &_
 "Installations And Prompt For Elevation}" : arAllowedNames(3,3) = "1"

arAllowedNames(4,0) = "EnableLUA" : arAllowedNames(4,1) = WSSSLP & "Security Options|"
arAllowedNames(4,2) = "User Account Control: Run All Administrators " &_
 "In Admin Approval Mode}" : arAllowedNames(4,3) = "1"

arAllowedNames(5,0) = "EnableSecureUIAPaths" : arAllowedNames(5,1) = WSSSLP & "Security Options|"
arAllowedNames(5,2) = "User Account Control: Only elevate UIAccess " &_
 "applications that are installed in secure locations}" : arAllowedNames(5,3) = "1"

arAllowedNames(6,0) = "EnableVirtualization" : arAllowedNames(6,1) = WSSSLP & "Security Options|"
arAllowedNames(6,2) = "User Account Control: Virtualize file and registry " &_
 "write failures to per-user locations}" : arAllowedNames(6,3) = "1"

arAllowedNames(7,0) = "FilterAdministratorToken" : arAllowedNames(7,1) = WSSSLP & "Security Options|"
arAllowedNames(7,2) = "User Account Control: Admin Approval Mode for " &_
 "the Built-in Administrator Account}" : arAllowedNames(7,3) = "0"

arAllowedNames(8,0) = "legalnoticecaption" : arAllowedNames(8,1) = WSSSLP & "Security Options|"
arAllowedNames(8,2) = "Interactive logon: Message title for users " &_
 "attempting to log on}" : arAllowedNames(8,3) = "***"

arAllowedNames(9,0) = "legalnoticetext" : arAllowedNames(9,1) = WSSSLP & "Security Options|"
arAllowedNames(9,2) = "Interactive logon: Message text for users " &_
 "attempting to log on}" : arAllowedNames(9,3) = "***"

arAllowedNames(10,0) = "PromptOnSecureDesktop" : arAllowedNames(10,1) = WSSSLP & "Security Options|"
arAllowedNames(10,2) = "User Account Control: Switch to the secure " & _
 "desktop when prompting for elevation}" : arAllowedNames(10,3) = "1"

arAllowedNames(11,0) = "scforceoption" : arAllowedNames(11,1) = WSSSLP & "Security Options|"
arAllowedNames(11,2) = "Interactive logon: Require smart card}" : arAllowedNames(11,3) = "***"

arAllowedNames(12,0) = "shutdownwithoutlogon" : arAllowedNames(12,1) = WSSSLP & "Security Options|"
arAllowedNames(12,2) = "Shutdown: Allow system to be shut down without " &_
 "having to log on}" : arAllowedNames(12,3) = "***"

arAllowedNames(13,0) = "undockwithoutlogon" : arAllowedNames(13,1) = WSSSLP & "Security Options|"
arAllowedNames(13,2) = "Devices: Allow undock without having to log on}" : arAllowedNames(13,3) = "***"

arAllowedNames(14,0) = "ValidateAdminCodeSignatures" : arAllowedNames(14,1) = WSSSLP & "Security Options|"
arAllowedNames(14,2) = "User Account Control: Only elevate executables " &_
 "that are signed and validated}" : arAllowedNames(14,3) = "***"

arAllowedNames(15,0) = "EnableUIADesktopToggle" : arAllowedNames(15,1) = WSSSLP & "Security Options|"
arAllowedNames(15,2) = "User Account Control: Allow UIAcess applications to prompt for elevation " &_
 "without using the secure desktop}" : arAllowedNames(15,3) = "0"

arAllowedNames(16,0) = "DisableCAD" : arAllowedNames(16,1) = WSSSLP & "Security Options|"
arAllowedNames(16,2) = "Interactive logon: Do not require CTRL+ALT+DEL}"
arAllowedNames(16,3) = "***"

GPRecognizer HKLM, strKey : ReDimGPOArrays


'has no effect in WMe
If strOS = "WXP" Or strOS = "WVA" or strOS = "WN7" Then

 strKey = "Software\Policies\Microsoft\Windows NT\SystemRestore"

 ReDim arRecNames(1,2)

 arRecNames(0,0) = "DisableSR" : arRecNames(0,1) = ATPL & SYS & "System Restore|"
 arRecNames(0,2) = "Turn off System Restore}"

 arRecNames(1,0) = "DisableConfig" : arRecNames(1,1) = ATPL & SYS & "System Restore|"
 arRecNames(1,2) = "Turn off Configuration}"

 GPRecognizer HKLM, strKey : ReDimGPOArrays

End If  'WXP/WVa/Wn7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#19. Enabled Wallpaper & Screen Saver

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim arBValue()

'title line string
strTitle = "Active Desktop and Wallpaper:"


'Active Desktop

'Active Desktop flag key
strKey = "Software\Microsoft\Windows\CurrentVersion\Explorer"

'get the ShellState binary array
On Error Resume Next
 intErrNum = oReg.GetBinaryValue (HKCU,strKey,"ShellState",arBValue)
On Error GoTo 0

'if array returned
If intErrNum = 0 And IsArray(arBValue) Then

 'if array contains Active Desktop flag
 If UBound(arBValue) >= 4 Then

  'if 0-based 4th array element contains 64 (AD flag set)
  If (arBValue(4) And 64) = 64 Then
   ReDim arBValue(0)  'recover array memory
   TitleLineWrite
   oFN.WriteLine vbCRLF & "Active Desktop may be enabled at this entry:" &_
    vbCRLF & "HKCU\" & strKey & "\ShellState"
  Else
   TitleLineWrite
   oFN.WriteLine vbCRLF & "Active Desktop may be disabled at this entry:" &_
    vbCRLF & "HKCU\" & strKey & "\ShellState"
  End If  'AD enabled?

 End If  'UBound>=4?

Else  'binary value not found

 If flagShowAll Then
  TitleLineWrite : oFN.WriteLine vbCRLF & "Active Desktop is not enabled."
 End If

End If  'binary value exists?


'Wallpaper

'check for AD wallpaper
strKey = "Software\Microsoft\Internet Explorer\Desktop\General"
strSubTitle = "Displayed if Active Desktop enabled and wallpaper not set by " &_
 strPolName & "Policy:" & vbCRLF & "HKCU\" & strKey & BS

On Error Resume Next
 intErrNum = oReg.GetStringValue (HKCU,strKey,"Wallpaper",strValue)
On Error GoTo 0

'if AD wallpaper value set
If intErrNum = 0 And strValue <> "" Then  'exc for W2K!

 'write value
 TitleLineWrite
 oFN.WriteLine "Wallpaper" & " = " & strValue

End If  'AD wallpaper value set?


'retrieve Wallpaper value
strKey = "Control Panel\Desktop"
strSubTitle = "Displayed if Active Desktop disabled and wallpaper not set by " &_
 strPolName & "Policy:" & vbCRLF & "HKCU\" & strKey & BS

On Error Resume Next
 intErrNum = oReg.GetStringValue (HKCU,strKey,"Wallpaper",strValue)
On Error GoTo 0

'if value set (exc for W2K!)
If intErrNum = 0 And strValue <> "" Then  'exc for W2K!

 TitleLineWrite
 'output wallpaper value
 oFN.WriteLine "Wallpaper" & " = " & strValue

Else  'WP value not present

 If flagShowAll Then
  TitleLineWrite
  oFN.WriteLine "Wallpaper" & " = (value not set)"
 End If

End If  'wallpaper value set?


'web content

'look for web content
strKey = "Software\Microsoft\Internet Explorer\Desktop\Components"
intErrNum = oReg.EnumKey(HKCU,strKey,arKeys)

strSubTitle = "Active Desktop web content (hidden if disabled):"
strSubSubTitle = "HKCU\" & strKey & BS

'if sub-keys exist
If IsArray(arKeys) Then

 'for each subkey
 For Each strSubKey in arKeys

  'retrieve DWORD containing web content activation flag
  On Error Resume Next
   intErrNum1 = oReg.GetDWORDValue (HKCU,strKey & BS & strSubKey,"Flags",intValue)
  On Error GoTo 0

  'if DWORD value set
  If intErrNum = 0 And intValue <> 0 Then

   'if DWORD contains 8192 (web content activation flag set)
   If (intValue And 8192) = 8192 Then

    'get web content descriptive values
    On Error Resume Next
     oReg.GetStringValue HKCU,strKey & BS & strSubKey,"FriendlyName",strValue1
     oReg.GetStringValue HKCU,strKey & BS & strSubKey,"Source",strValue2
     oReg.GetStringValue HKCU,strKey & BS & strSubKey,"SubscribedURL",strValue3
    On Error GoTo 0

    TitleLineWrite

    'write web content descriptive values
    oFN.WriteLine vbCRLF & strSubKey & BS
    oFN.WriteLine "FriendlyName" & " = " & strValue1
    oFN.WriteLine "Source" & " = " & strValue2
    oFN.WriteLine "SubscribedURL" & " = " & strValue3

   End If  'web content active?

  End If  'web content DWORD value set?

 Next  'web content subkey

End If  'web content subkeys exist

'output titles not already done
If flagShowAll Then TitleLineWrite

strSubTitle = "" : strSubSubTitle = ""


'Screen Saver

If strOS <> "W98" And strOS <> "WME" Then

Dim strLFN : strLFN = ""  'screen saver LFN
Dim strExt : strExt = ""  'wallpaper file extension
strWarn = ""

strTitle = "Enabled Screen Saver:"

strKey = "Control Panel\Desktop"
strSubTitle = "HKCU\" & strKey & BS

'get the screen saver name
On Error Resume Next
 intErrNum = oReg.GetStringValue (HKCU,strKey,"Scrnsave.exe",strValue)
On Error GoTo 0

 'if Scrnsave.exe value exists And value set (exc for W2K!)
 ' And value <> "(NONE)" (NT4 default)
 If intErrNum = 0 And strValue <> "" And LCase(strValue) <> "(none)" Then

  'get screen saver LFN if file exists
  If Fso.FileExists(strValue) Then

   'create (but don't save) shortcut
   Dim oSC : Set oSC = Wshso.CreateShortcut("getLFN.lnk")
   'set & retrieve target path
   oSC.TargetPath = strValue
   strLFN = Fso.GetFile(oSC.TargetPath).Name
   Set oSC=Nothing

   'set up LFN string if SFN <> LFN
   If LCase(strLFN) = LCase(Fso.GetFileName(strValue)) Then
    strLFN = ""
   Else
    strLFN = " (" & strLFN & ")"
   End If

  End If  'screen saver file exists?

  TitleLineWrite

  oFN.WriteLine "SCRNSAVE.EXE" & " = " &_
   strValue & strLFN & CoName(IDExe(strValue))

 Else  'Scrnsave.exe value doesn't exist

  'if ShowAll, output title line
  If flagShowAll Then

   TitleLineWrite
   oFN.WriteLine "SCRNSAVE.EXE" & " = (value not set)"

  End If  'flagShowAll

 End If  'Scrnsave.exe value exists?

End If  'strOS <> W98/WME?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#20. WIN.INI load/run, SYSTEM.INI shell/scrnsave.exe, WINSTART.BAT, IniFileMapping
'     W98/WMe - check inside WIN.INI (load=, run=), SYSTEM.INI (shell=, scrnsave.exe=)
'     W98     - list contents of non-empty WINSTART.BAT
'     NT4+    - check for non-default IniFileMapping values

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

If strOS = "W98" Or strOS = "WME" Then

 strTitle = "WIN.INI & SYSTEM.INI launch points:"

 Dim oSCF  'System Configuration File
 'true if in INI-file section containing targeted lines
 Dim flagSection : flagSection = False

 strSubTitle = "WIN.INI" & vbCRLF & "[windows]"

 'open WIN.INI
 Set oSCF = Fso.OpenTextFile (strFPWF & "\WIN.INI",1)

 'for each line of WIN.INI
 Do While Not oSCF.AtEndOfStream

  'read a line
  strLine = oSCF.ReadLine

  'if not a blank/comment line And inside [windows] section
  If Trim(strLine) <> "" And Left(LTrim(strLine),1) <> ";" Then

   If flagSection Then

    'if line is beginning of another section
    If Left(LTrim(strLine),1) = "[" Then
     'toggle flag to false and exit Do
     flagSection = False : Exit Do
    End If  'next section?

    'input line, verb, expected contents, disk
    IniInfParse strLine, "load", "", ""
    IniInfParse strLine, "run", "", ""

   End If  'flagSection?

   'if first 9 chars of line = [windows], then in the right section
   'so toggle flagSection to True
   If LCase(Left(LTrim(strLine),9)) = "[windows]" Then flagSection = True

  End If  'blank/comment line?

 Loop  'next line of WIN.INI

 oSCF.Close  'close WIN.INI
 flagSection = False

 strSubTitle = "SYSTEM.INI" & vbCRLF & "[boot]"

 'open SYSTEM.INI
 Set oSCF = Fso.OpenTextFile (strFPWF & "\SYSTEM.INI",1)

 'for each line of SYSTEM.INI
 Do While Not oSCF.AtEndOfStream

  strLine = oSCF.ReadLine

  'if not a blank/comment line And inside [windows] section
  If Trim(strLine) <> "" And Left(LTrim(strLine),1) <> ";" Then

   'if inside [boot] section
   If flagSection Then

    If Left(LTrim(strLine),1) = "[" Then
     'toggle flagSection and exit
     flagSection = False : Exit Do
    End If  'shell line?

    IniInfParse strLine, "shell", "explorer.exe", ""
    IniInfParse strLine, "scrnsave.exe", "anything", ""

   End If  'inside boot section?

   'if first 6 chars of line = [boot], then in the right section
   'so toggle flagSection to True
   If LCase(Left(LTrim(strLine),6)) = "[boot]" Then flagSection = True

  End If  'blank/comment line?

 Loop

 oSCF.Close

 strSubTitle = ""

 'for W98 only
 If strOS = "W98" Then

   strTitle = "WINSTART.BAT contents:"

  'open WINSTART.BAT if it exists
  If Fso.FileExists(strFPWF & "\WINSTART.BAT") Then

   Set oSCF = Fso.OpenTextFile (strFPWF & "\WINSTART.BAT",1)

   'for each line of WINSTART.BAT
   Do While Not oSCF.AtEndOfStream

    strLine = oSCF.ReadLine
    If strLine <> "" Then  'examine line if it's not a CR

     If Len(strLine) >= 3 Then  'test against REM if long enough

      'if not REM, then output
      If LCase(Left(LTrim(strLine),3)) <> "rem" Then
       If strTitle <> "" Then
        TitleLineWrite : oFN.WriteBlankLines(1)
       End If
       oFN.WriteLine strLine
      End If

     Else  'len 1-2

      TitleLineWrite : oFN.WriteLine strLine

     End If  'len < 3?

    End If  'carriage return?

   Loop  'WINSTART.BAT lines

   oSCF.Close : Set oSCF=Nothing

  Else  'WINSTART.BAT doesn't exist

   'if ShowAll, write title lines
   If flagShowAll Then
    TitleLineWrite : oFN.WriteLine vbCRLF & "(file not found)"
   End If

  End If  'WINSTART.BAT exists?

 End If  'W98?

Else  'NT4+

 strTitle = "IniFileMapping Pointers to .INI Files:"
 strSubTitle = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\"

 'Allowed INI-File Sections & Registry Locations
 Dim dictAIFSRL : Set dictAIFSRL = CreateObject("Scripting.Dictionary")

 strSubSubTitle = "ImageFileExecutionOptions.ini\"
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\ImageFileExecutionOptions.ini"
 strValue = "SYS:Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

 ChkDefaultValue strKey, strValue  'compare default value to strValue

 strSubSubTitle = "System.ini\"
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini"

 If strOS = "WVA" Or strOS = "WN7" Then
  dictAIFSRL.Add "drivers","SYS:Microsoft\Windows NT\CurrentVersion\Drivers"
 Else
  dictAIFSRL.Add "drivers","#SYS:Microsoft\Windows NT\CurrentVersion\drivers"
 End If
 dictAIFSRL.Add "drivers32","SYS:Microsoft\Windows NT\CurrentVersion\Drivers32"
 dictAIFSRL.Add "NonWindowsApp","SYS:Microsoft\Windows NT\CurrentVersion\WOW\NonWindowsApp"
 dictAIFSRL.Add "standard","SYS:Microsoft\Windows NT\CurrentVersion\WOW\standard"

 ChkNameValues strKey, dictAIFSRL, False  'compare name/value pairs to allowed

 dictAIFSRL.RemoveAll

 strSubSubTitle = "system.ini\boot\"
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot"
 strValue = "SYS:Microsoft\Windows NT\CurrentVersion\WOW\boot"

 ChkDefaultValue strKey, strValue  'compare default value to strValue

 dictAIFSRL.Add "SCRNSAVE.EXE","USR:Control Panel\Desktop"
 dictAIFSRL.Add "Shell","SYS:Microsoft\Windows NT\CurrentVersion\Winlogon"

 ChkNameValues strKey, dictAIFSRL, True  'compare name/value pairs to allowed
                                         'resolve unallowed value

 dictAIFSRL.RemoveAll

 strSubSubTitle = "win.ini\"
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\win.ini"

 dictAIFSRL.Add "AeDebug","SYS:Microsoft\Windows NT\CurrentVersion\AeDebug"
 dictAIFSRL.Add "Devices","USR:Software\Microsoft\Windows NT\CurrentVersion\Devices"
 dictAIFSRL.Add "Winlogon","SYS:Microsoft\Windows NT\CurrentVersion\Winlogon"

 ChkNameValues strKey, dictAIFSRL, False  'compare name/value pairs to allowed

 dictAIFSRL.RemoveAll

 strSubSubTitle = "win.ini\Windows\"
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\win.ini\Windows"
 strValue = "USR:Software\Microsoft\Windows NT\CurrentVersion\Windows"

 ChkDefaultValue strKey, strValue  'compare default value to strValue

 If strOS = "WVA" Or strOS = "WN7" Then
  dictAIFSRL.Add "AppInit_DLLs","SYS:MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINDOWS"
 Else
  dictAIFSRL.Add "AppInit_DLLs","SYS:Microsoft\Windows NT\CurrentVersion\Windows"
 End If

 ChkNameValues strKey, dictAIFSRL, True  'compare name/value pairs to allowed
                                         'resolve unallowed value

 dictAIFSRL.RemoveAll

End If  'strOS = W98/WME

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
strWarn = "" : strOut = ""

End If  'SecTest?




'#21. AUTORUN.INF in root directory of local fixed disks

'*any* HKLM value trumps *any* HKCU value

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'WMe, WXP SP2, WVa & Wn7 do not launch AUTORUN.INF on local fixed disks
If strOS <> "WME" And strOSLong <> "Windows XP SP2" _
 And strOS <> "WVA" And strOS <> "WN7" Then

 'fixed disk, DWORD value, binary value array, AutoRun.Inf file,
 Dim oDisk, hVal, arBVal, oARI

 strTitle = "Autostart via AUTORUN.INF on local fixed drives:"

 'array of fixed disks
 Public arFixedDisks()

 'Disk Letter dictionary (needed to calculate power of 2)
 'dictDL.Item(6) returns "G:"
 Public dictDL : Set dictDL = CreateObject("Scripting.Dictionary")
 dictDL.Add  0, "A:" : dictDL.Add  1, "B:" : dictDL.Add  2, "C:"
 dictDL.Add  3, "D:" : dictDL.Add  4, "E:" : dictDL.Add  5, "F:"
 dictDL.Add  6, "G:" : dictDL.Add  7, "H:" : dictDL.Add  8, "I:"
 dictDL.Add  9, "J:" : dictDL.Add 10, "K:" : dictDL.Add 11, "L:"
 dictDL.Add 12, "M:" : dictDL.Add 13, "N:" : dictDL.Add 14, "O:"
 dictDL.Add 15, "P:" : dictDL.Add 16, "Q:" : dictDL.Add 17, "R:"
 dictDL.Add 18, "S:" : dictDL.Add 19, "T:" : dictDL.Add 20, "U:"
 dictDL.Add 21, "V:" : dictDL.Add 22, "W:" : dictDL.Add 23, "X:"
 dictDL.Add 24, "Y:" : dictDL.Add 25, "Z:"

 'assume HKLM NoDriveTypeAutoRun Fixed Disks Enabled
 Public flagHKLM_NDTAR_FDE : flagHKLM_NDTAR_FDE = True
 'assume HKCU NoDriveTypeAutoRun Fixed Disks Enabled
 Public flagHKCU_NDTAR_FDE : flagHKCU_NDTAR_FDE = True

 'assume HKLM NoDriveTypeAutoRun value does NOT exist
 Public flagHKLM_NDTAR : flagHKLM_NDTAR = False
 'assume HKCU NoDriveTypeAutoRun value does NOT exist (unused, passed for consistency)
 Public flagHKCU_NDTAR : flagHKCU_NDTAR = False

 'assume HKLM NoDriveAutoRun value does NOT exist
 Public flagHKLM_NDAR : flagHKLM_NDAR = False
 'assume HKCU NoDriveAutoRun value does NOT exist (unused, passed for consistency)
 Public flagHKCU_NDAR : flagHKCU_NDAR = False

 strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

  'check NDTAR/NDTAR_FDE values in HKLM, toggle flag if needed
  NDTAR HKLM, flagHKLM_NDTAR, flagHKLM_NDTAR_FDE
  'if HKLM NDTAR value not found, check NDTAR/NDTAR_FDE values in HKCU
  If Not flagHKLM_NDTAR Then NDTAR HKCU, flagHKCU_NDTAR, flagHKCU_NDTAR_FDE

 'if NoDriveTypeAutoRun permits autorun on fixed disks, look at
 'individual disks
 If flagHKLM_NDTAR_FDE And flagHKCU_NDTAR_FDE Then

  'enumerate fixed disks
  Set colDisks = GetObject("winmgmts:\root\cimv2")._
   ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")

  j = 0

  'fmt of DeviceID & Name is "A:"
  For Each oDisk in colDisks

   'for every dict entry
   For i = 0 To 25

    'find dictionary element number for drive letter
    If dictDL.Item(i) = oDisk.DeviceID Then

     'store disk letter, power of two for that letter,
     'set autorun flag to True, increment counter
     ReDim Preserve arFixedDisks(2,j)
     arFixedDisks(0,j) = oDisk.DeviceID
     arFixedDisks(1,j) = 2^i
     arFixedDisks(2,j) = True
     j = j + 1

    End If  'dict drive letter located?

   Next  'dict entry

  Next  'disk in colDisks

  NDAR HKLM, flagHKLM_NDAR

  If Not flagHKLM_NDAR Then NDAR HKCU, flagHKCU_NDAR

  'for every fixed disk
  For i = 0 To UBound(arFixedDisks,2)

   strSubTitle = arFixedDisks(0,i) & BS

   'if autorun enabled
   If arFixedDisks(2,i) Then

    'look for AUTORUN.INF in the root
    If Fso.FileExists(arFixedDisks(0,i) & "\autorun.inf") Then

     'open AUTORUN.INF if found
     Set oARI = Fso.OpenTextFile (arFixedDisks(0,i) & "\autorun.inf",1)

     'for each line of AUTORUN.INF
     Do While Not oARI.AtEndOfStream

      'read a line
      strLine = oARI.ReadLine

      'look for "open" or "shellexecute" statements
      IniInfParse strLine, "open", "", arFixedDisks(0,i)
      IniInfParse strLine, "shellexecute", "", arFixedDisks(0,i)

     Loop  'next AUTORUN.INF line

     oARI.Close : Set oARI=Nothing  'close AUTORUN.INF

     'if no verbs found And ShowAll
     If strSubTitle <> "" And flagShowAll Then

      TitleLineWrite

      oFN.WriteLine "AUTORUN.INF -> (" & "open" &_
       " & " & "shellexecute" & " lines not found)"

     End If  'ShowAll?

    Else  'AUTORUN.INF not found in root

     'if ShowAll
     If flagShowAll Then

      TitleLineWrite

      'output file not found message
      oFN.WriteLine "AUTORUN.INF -> (file not found)"

     End If  'ShowAll?

    End If  'AUTORUN.INF exists in root?

   End If  'autorun enabled on drive?

  Next  'fixed disk

 End If  'NoDriveTypeAutoRun enables autorun on fixed disks?

 dictDL.RemoveAll : Set dictDL=Nothing

End If  'strOS <> WME/WXP SP2/WVA/WN7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#22. HKLM... Explorer\AutoplayHandlers\Handlers

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
' And OS = WXP or WVA or WN7
If (Not flagTest Or (flagTest And SecTest)) And (strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7") Then

'InvokeProgID, InvokeVerb, Command/DropTarget subverbs, found subverbs,
'path from HKLM\SOFTWARE\Classes to shell\verb
Dim strHandlerSubKey, strVerb, arSubVerbs, strSubVerb, strClass2Verb, strHive, strCLSIDVerb, flagSUBAllow
Dim strCLSIDSubKey  'path to one of four CLSID verbs

Dim strCLSIDVerbValue

Dim strProvider  'Provider value
'2 row x 3 col array, col 0: subverb; col 1: value; col 2: found?
Dim arAllowedSubVerbs (1,2)
arAllowedSubVerbs(0,0) = "Command"
arAllowedSubVerbs(0,1) = ""
arAllowedSubVerbs(1,0) = "DropTarget"
arAllowedSubVerbs(1,1) = "CLSID"
'four possible CLSID verbs
Dim arCLSIDVerbs : arCLSIDVerbs = Array("InProcServer32","LocalServer32","ProgID","VersionIndependentProgID")
'are Provider/InitCmdLine/CLSID/InvokeProgID executables default?
Dim flagAllowProvider, flagAllowICL, flagAllowCLSIDServer, flagAllowInvokeProgID

'mix of Provider, ICL, CLSID Server values that cover all executables referred by Handler names
Dim arAllowedHandlerGrammar() : ReDim arAllowedHandlerGrammar(87)

'WXP Home
arAllowedHandlerGrammar(0) = "@%SystemRoot%\system32\SHELL32.dll,-17170"
arAllowedHandlerGrammar(1) = strFPWF & "\Explorer.exe /idlist,%I,%L"
arAllowedHandlerGrammar(2) = "@%SystemRoot%\system32\SHELL32.dll,-17155"
arAllowedHandlerGrammar(3) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /device:AudioCD " & DQ & "%L" & DQ
arAllowedHandlerGrammar(4) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:4 /device:DVD " & DQ & "%L" & DQ
arAllowedHandlerGrammar(5) = strFPSF & "\wmpshell.dll"
arAllowedHandlerGrammar(6) = "@%SystemRoot%\system32\SHELL32.dll,-17159"
arAllowedHandlerGrammar(7) = "rundll32.exe " & strFPWF & "\system32\shimgvw.dll," &_
 "ImageView_Fullscreen %1"
arAllowedHandlerGrammar(8) = strFPSF & "\photowiz.dll"
arAllowedHandlerGrammar(9) = "Windows Explorer"
arAllowedHandlerGrammar(10) = "PromptEachTime"
arAllowedHandlerGrammar(11) = "rundll32.exe shell32.dll,SHCreateLocalServerRunDll " &_
 "{995C996E-D918-4a8c-A302-45719A6F4EA7}"
arAllowedHandlerGrammar(12) = "PromptEachTimeNoContent"
arAllowedHandlerGrammar(13) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /RipAudioCD " & DQ & "%L" & DQ
arAllowedHandlerGrammar(14) = "@%SystemRoot%\system32\SHELL32.dll,-17157"
arAllowedHandlerGrammar(15) = "rundll32.exe " & strFPWF & "\system32\shimgvw.dll," &_
 "ImageView_COMServer {00E7B358-F65B-4dcf-83DF-CD026B94BFD4}"
arAllowedHandlerGrammar(16) = "@" & strPgmFilesDir & "\Movie Maker\wmmres.dll,-61424"
arAllowedHandlerGrammar(17) = DQ & strPgmFilesDir & "\Movie Maker\moviemk.exe" & DQ & " /RECORD"
arAllowedHandlerGrammar(18) = "rundll32.exe shell32.dll,SHCreateLocalServerRunDll " &_
 "{FFB8655F-81B9-4fce-B89C-9A6BA76D13E7}"
arAllowedHandlerGrammar(19) = strFPSF & "\wiadefui.dll"
arAllowedHandlerGrammar(20) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /task:PortableDevice"
arAllowedHandlerGrammar(21) = "@" & strPgmFilesDir & "\Movie Maker\wmmres.dll,-61424"
arAllowedHandlerGrammar(22) = "@wmploc.dll,-6502"
arAllowedHandlerGrammar(23) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /Task:PortableDevice /Device:" & DQ & "%L" & DQ

'WVA
arAllowedHandlerGrammar(24) = "@" & strFPWF & "\eHome\ehdrop.dll,-115"
arAllowedHandlerGrammar(25) = strFPWF & "\eHome\ehdrop.dll"
arAllowedHandlerGrammar(26) = "@" & strFPSF & "\shell32.dll,-17417"
arAllowedHandlerGrammar(27) = strFPSF & "\shell32.dll,PrepareDiscForBurnRunDll %L"
arAllowedHandlerGrammar(28) = "@emdmgmt.dll,-200"
arAllowedHandlerGrammar(29) = "rundll32.exe emdmgmt.dll,EMDMgmtLaunchProperties %L"
arAllowedHandlerGrammar(30) = DQ & strPgmFilesDir & "\Movie Maker\dvdmaker.exe" &_
 DQ & " -drive:%L" & DQ
arAllowedHandlerGrammar(31) = strFPWF & "\Explorer.exe /separate,/idlist,%I,%L"
arAllowedHandlerGrammar(32) = "@" & strPgmFilesDir & "\Windows Photo Gallery\PhotoAcq.dll,-401"
arAllowedHandlerGrammar(33) = DQ & strFPSF & "\rundll32.exe" & DQ &_
 " " & DQ & strPgmFilesDir & "\Windows Photo Gallery\PhotoAcq.dll" & DQ &_
 ",AutoplayComServerW {00f2b433-44e4-4d88-b2b0-2698a0a91dba}"
arAllowedHandlerGrammar(34) = strFPSF & "\rundll32.exe " & strFPWF &_
 "\system32\shell32.dll,PrepareDiscForBurnRunDll %L"
arAllowedHandlerGrammar(35) = "@" & strPgmFilesDir & "\movie maker\dvdmaker.exe,-61403"
arAllowedHandlerGrammar(36) = DQ & strPgmFilesDir & "\Movie Maker\dvdmaker.exe" &_
 DQ & " -drive:%L"
arAllowedHandlerGrammar(37) = strPgmFilesDir & "\Windows Photo Gallery\PhotoAcq.dll"
arAllowedHandlerGrammar(38) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:4 /device:VCD " & DQ & "%L" & DQ
arAllowedHandlerGrammar(39) = "@" & strFPSF & "\shell32.dll,-17411"
arAllowedHandlerGrammar(40) = strFPSF & "\rundll32.exe shell32.dll," &_
 "SHCreateLocalServerRunDll {995C996E-D918-4a8c-A302-45719A6F4EA7}"
arAllowedHandlerGrammar(41) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /RipAudioCD " & DQ & "%L" & DQ
arAllowedHandlerGrammar(42) = "@%SystemRoot%\system32\audiodev.dll,-501"
arAllowedHandlerGrammar(43) = "::{21EC2020-3AEA-1069-A2DD-08002B30309D}\" &_
 "::{640167b4-59b0-47a6-b335-a6b3c0695aea}"
arAllowedHandlerGrammar(44) = strFPSF & "\rundll32.exe shell32.dll," &_
 "SHCreateLocalServerRunDll {FFB8655F-81B9-4fce-B89C-9A6BA76D13E7}"
arAllowedHandlerGrammar(45) = "@" & strPgmFilesDir & "\Windows Photo Gallery\PhotoViewer.dll,-3067"
arAllowedHandlerGrammar(46) = DQ & strFPSF & "\rundll32.exe" & DQ &_
 " " & DQ & strPgmFilesDir & "\Windows Photo Gallery\PhotoViewer.dll" & DQ &_
 ",ImageView_COMServer {9D687A4C-1404-41ef-A089-883B6FBECDE6}"
arAllowedHandlerGrammar(47) = "@" & strPgmFilesDir & "\Movie Maker\CaptureWizard.exe,-61403"
arAllowedHandlerGrammar(48) = "CaptureWizard"
arAllowedHandlerGrammar(49) = DQ & strPgmFilesDir & "\Movie Maker\VideoCameraAutoPlayManager.exe" & DQ
arAllowedHandlerGrammar(50) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /Task:CDWrite /Device:" & DQ & "%L" & DQ
arAllowedHandlerGrammar(51) = DQ & strPgmFilesDir & "\Windows Media Player\wmplayer.exe" &_
 DQ & " /prefetch:3 /Task:DVDWrite /Device:" & DQ & "%L" & DQ
arAllowedHandlerGrammar(52) = "@%windir%\system32\migwiz\MIGUIRes.dll,-12095"
arAllowedHandlerGrammar(53) = "MigAutoPlay.exe"
arAllowedHandlerGrammar(54) = "/NetworkConfig;rundll32;xwizards.dll,RunWizard {34c219bd-85c1-4338-95e8-788a36901dc2} /z %s"
arAllowedHandlerGrammar(55) = "@" & strFPSF & "\wpdshext.dll,-503"
arAllowedHandlerGrammar(56) = "@" & strFPSF & "\wpdshext.dll,-501"
arAllowedHandlerGrammar(57) = strFPSF & "\WPDShextAutoplay.exe"
arAllowedHandlerGrammar(58) = "/NetworkConfig;rundll32;xwizards.dll," &_
 "RunWizard {34c219bd-85c1-4338-95e8-788a36901dc2} /z %s"

'WXP Pro
arAllowedHandlerGrammar(59) = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\" &_
 "::{21EC2020-3AEA-1069-A2DD-08002B30309D}\::{640167b4-59b0-47a6-b335-a6b3c0695aea}"
arAllowedHandlerGrammar(60) = "@" & strPgmFilesDir & "\Movie Maker\wmm2res.dll,-100"
'language-specific!
arAllowedHandlerGrammar(61) = "@" & strPgmFilesDir & "\Movie Maker\1033\wmm2res.dll,-100"
arAllowedHandlerGrammar(62) = DQ & strPgmFilesDir & "\Movie Maker\moviemk.exe" &_
 DQ & " /RECORD"
arAllowedHandlerGrammar(63) = DQ & strPgmFilesDir &_
 "\Windows Media Player\wmlaunch.exe" & DQ
arAllowedHandlerGrammar(64) = "@%systemroot%\System32\wiaacmgr.exe,-101"
arAllowedHandlerGrammar(65) = strFPSF & "\svchost.exe"

'WN7
arAllowedHandlerGrammar(66) = "@%windir%\system32\migwiz\wet.dll,-588"
arAllowedHandlerGrammar(67) = "@" & strFPSF & "\sysmain.dll,-200"
arAllowedHandlerGrammar(68) = strFPSF & "\rundll32.exe " & strFPSF & "\sysmain.dll,RDBMgmtLaunchProperties %L"
arAllowedHandlerGrammar(69) = "@" & strPgmFilesDir & "\DVD maker\dvdmaker.exe,-61403"
arAllowedHandlerGrammar(70) = DQ & strPgmFilesDir & "\DVD Maker\dvdmaker.exe" & DQ & " -drive:%L"
arAllowedHandlerGrammar(71) = "@" & strFPSF & "\EhStorShell.dll,-106"
arAllowedHandlerGrammar(72) = strFPSF & "\EhStorShell.dll"
arAllowedHandlerGrammar(73) = "Authorize"
arAllowedHandlerGrammar(74) = "@" & strFPSF & "\shell32.dll,-17411"
arAllowedHandlerGrammar(75) = strFPWF & "\Explorer.exe"
arAllowedHandlerGrammar(76) = "@" & strPgmFilesDir & "\Windows Photo Viewer\PhotoAcq.dll,-401"
arAllowedHandlerGrammar(77) = DQ & strFPSF & "\rundll32.exe" & DQ & Space(1) & DQ & strPgmFilesDir & "\Windows Photo Viewer\PhotoAcq.dll" & DQ & ",AutoplayComServerW {00f2b433-44e4-4d88-b2b0-2698a0a91dba}"
arAllowedHandlerGrammar(78) = strPgmFilesDir & "\Windows Photo Viewer\PhotoAcq.dll"
arAllowedHandlerGrammar(79) = "@C:\Windows\system32\sdautoplay.dll,-100"
arAllowedHandlerGrammar(80) = strFPSF & "\sdclt.exe /CONFIGELEV %L"
arAllowedHandlerGrammar(81) = strFPSF & "\sdclt.exe /KICKOFFELEV"
arAllowedHandlerGrammar(82) = "@" & strPgmFilesDir & "\Windows Photo Viewer\PhotoViewer.dll,-3067"
arAllowedHandlerGrammar(83) = DQ & strFPSF & "\rundll32.exe" & DQ & Space(1) & DQ & strPgmFilesDir & "\Windows Photo Viewer\PhotoViewer.dll" & DQ  & ",ImageView_COMServer {9D687A4C-1404-41ef-A089-883B6FBECDE6}"
arAllowedHandlerGrammar(84) = "@" & strFPSF & "\wzcdlg.dll,-2102"
arAllowedHandlerGrammar(85) = strFPSF & "\rundll32.exe " & strFPSF & "\wzcdlg.dll,ImportFlashProfile %L"

'WVA (cont.)
arAllowedHandlerGrammar(86) = "@" & strFPSF & "\EhStorShell.dll,-108"
arAllowedHandlerGrammar(87) = strFPSF & "\EhStorShell.dll"

strTitle = "Windows Portable Device AutoPlay Handlers"

strKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers"
strSubTitle = "HKLM\" & strKey & BS

'set up CLSID string & spacing for this section
strCTHL = LIP & "CLSID} = " : intCTHLS = intCS

'find all the Handlers
oReg.EnumKey HKLM,strKey,arKeys

'if Handlers found
If IsArray(arKeys) Then

 'for each Handler
 For Each strHandlerSubKey In arKeys

  flagFound = False : flagAllow = False

' InvokeProgID & InvokeVerb
' -------------------------

  'Shell\verb\Command/DropValue values not found
  arAllowedSubVerbs(0,2) = False : arAllowedSubVerbs(1,2) = False

  'look for InvokeProgID & InvokeVerb
  On Error Resume Next
   intErrNum1 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"InvokeProgID",strProgID)
   intErrNum2 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"InvokeVerb",strVerb)
  On Error GoTo 0

  'if InvokeProgID & InvokeVerb both found
  If intErrNum1 = 0 And intErrNum2 = 0 Then

   'intialize variables & flag
   strValue = "" : strCLSIDVerb = "" : strCLSIDVerbValue = "" : strCLSIDTitle = ""
   strProvider = ""

   flagAllowProvider = True  'start out with Handler Provider is default

   'set up SubSubTitle
   strSubSubTitle = strHandlerSubKey & BS & vbCRLF &_
    "InvokeProgID" & " = " & strProgID & vbCRLF &_
    "InvokeVerb" & " = " & strVerb

   'look for Provider
   On Error Resume Next
    intErrNum5 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"Provider",strProvider)
   On Error GoTo 0

   'if Provider found
   If intErrNum5 = 0 And strProvider <> "" Then

    'modify SubSubTitle
    strSubSubTitle = strHandlerSubKey & BS & vbCRLF &_
     "Provider" & " = " & strProvider & vbCRLF &_
     "InvokeProgID" & " = " & strProgID & vbCRLF &_
     "InvokeVerb" & " = " & strVerb

    flagAllowProvider = False  'assume Handler Provider is not default

    'check to see if Provider value is default
    For kk = 0 To UBound(arAllowedHandlerGrammar)

     If LCase(Trim(strProvider)) = LCase(arAllowedHandlerGrammar(kk)) Then
      flagAllowProvider = True : Exit For
     End If

    Next  'arAllowedHandlerGrammar member

   End If  'strProvider found?

   'assemble InvokeProgID + Verb phrase
   strClass2Verb = "SOFTWARE\Classes\" & strProgID & "\shell\" & strVerb

   'look for phrase in each hive
   For ii = 0 To 1

    'look for phrase subverbs
    oReg.EnumKey arHives(ii,1),strClass2Verb,arSubVerbs

    'if subverbs found
    If IsArray(arSubVerbs) Then

     'for each subverb found
     For Each strSubVerb In arSubVerbs

      'intialize flags
      flagAllowCLSIDServer = False  'Handler action not default
      flagAllowInvokeProgID = False  'Handler action not default
      flagAllow = False  'TRUE if Provider & CLSIDServer are default

      'check if subverb either Command or DropTarget
      For jj = 0 To UBound(arAllowedSubVerbs,1)

       'since this For _must_ be traversed for all index values, an
       'Exit for a subverb already found cannot be placed here

       'if command or droptarget found
       If LCase(strSubVerb) = LCase(arAllowedSubVerbs(jj,0)) Then

        'exit if subverb already found
        If arAllowedSubVerbs(jj,2) Then Exit For

        'retrieve the Command default value or DropTarget CLSID value
        On Error Resume Next
         intErrNum4 = oReg.GetStringValue (arHives(ii,1),strClass2Verb &_
          BS & strSubVerb,arAllowedSubVerbs(jj,1),strValue)
        On Error GoTo 0

        'if the value exists
        If intErrNum4 = 0 And strValue <> "" Then

         'toggle flagFound flag to avoid subsequent sections
         flagFound = True

         'if value is a CLSID
         If IsCLSID(strValue) Then

          'resolve the CLSID & set Allow flag
          CLSIDPop strValue, UBound(arCLSIDVerbs), flagAllowCLSIDServer, _
           strHive, strCLSIDVerb, strCLSIDVerbValue, strCLSIDTitle

          If strCLSIDVerbValue <> "" Then

           arAllowedSubVerbs(jj,2) = True

           'toggle flagAllow if Provider & CLSIDServer are default
           If flagAllowCLSIDServer And flagAllowProvider Then _
            flagAllow = True

           'output required if not default Or ShowAll
           If Not flagAllow Or flagShowAll Then

            TitleLineWrite
            oFN.WriteLine SOCA(arHives(ii,0) & BS & strClass2Verb) & BS &_
             strSubVerb & BS & arAllowedSubVerbs(jj,1) & " = " &_
              strValue
            oFN.WriteLine "  -> {" & strHive & strCTHL & strCLSIDTitle
            oFN.WriteLine Space(intCTHLS) & BS & strCLSIDVerb & "\(Default) = " &_
             strCLSIDVerbValue & CoName(IDExe(strCLSIDVerbValue))

            'toggle Command/DropTarget found flag
            arAllowedSubVerbs(jj,2) = True : Exit For

           End If  'output required?

          End If  'strCLSIDVerbValue not empty?

         Else  'IsCLSID = False, so this is a Command verb

          'check to see if Command value is default
          For kk = 0 To UBound(arAllowedHandlerGrammar)

           If arAllowedSubVerbs(jj,2) = True Then Exit For

           'if default, toggle Command/DropTarget found flag & default flag
           If LCase(Trim(strValue)) = LCase(arAllowedHandlerGrammar(kk)) Then
            arAllowedSubVerbs(jj,2) = True : flagAllowInvokeProgID = True : Exit For
           End If

          Next

          'toggle flagAllow if Provider & CLSIDServer are default
          If flagAllowInvokeProgID And flagAllowProvider Then _
           flagAllow = True

          'output required if not default or ShowAll
          If Not flagAllow Or flagShowAll Then

           TitleLineWrite
           oFN.WriteLine SOCA(arHives(ii,0) & BS & strClass2Verb) &_
            BS & strSubVerb & BS & arAllowedSubVerbs(jj,1) &_
            "(Default) = " & strValue & CoName(IDExe(strValue))
           arAllowedSubVerbs(jj,2) = True : Exit For

          End If  'output required?

         End If  'IsCLSID?

        End If  'Command\(Default)/DropTarget\CLSID value exists?

       End If  'Command/DropTarget verb exists?

      Next  'jj arAllowedSubVerb

     Next  'arSubVerb

    End If  'arSubVerbs exists?

   Next  'ii hive

  End If  'InvokeProgID & Invoke Verb (intErrNum1/2) both found?



' ProgID & Provider
' -----------------

  'if Handler action not defined by InvokeProgID & InvokeVerb,
  'try ProgID & Provider
  If Not flagFound Then

   'look for ProgID & Provider
   On Error Resume Next
    intErrNum1 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"ProgID",strProgID)
    intErrNum2 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"Provider",strProvider)
   On Error GoTo 0

   'if ProgID & Provider both found
   If intErrNum1 = 0 And intErrNum2 = 0 Then

    'intialize variables & flags
    strValue = "" : strValue3 = "" : strCLSIDVerb = "" : strCLSIDVerbValue = ""
    strCLSIDTitle = ""

    flagAllowCLSIDServer = False  'Handler action not permitted/default
    flagAllowProvider = False  'Handler Provider is not permitted/default
    flagAllowICL = True  'Handler InitCmdLine is permitted/default
    flagAllow = False  'Handler is not permitted/default

    'check to see if Provider value is default
    For kk = 0 To UBound(arAllowedHandlerGrammar)

     If LCase(Trim(strProvider)) = LCase(arAllowedHandlerGrammar(kk)) Then
      flagAllowProvider = True : Exit For
     End If

    Next  'arAllowedHandlerGrammar member

    strSubSubTitle = strHandlerSubKey & BS & vbCRLF &_
     "Provider" & " = " & strProvider & vbCRLF &_
     "ProgID" & " = " & strProgID

    'assemble ProgID\CLSID key
    strClass2Verb = "SOFTWARE\Classes\" & strProgID & "\CLSID"

    'look in each hive
    For ii = 0 To 1

     'exit if CLSID server already found
     If flagFound Then Exit For

     'look for ProgID\CLSID default value
     On Error Resume Next
      intErrNum2 = oReg.GetStringValue (arHives(ii,1),strClass2Verb,"",strValue)
     On Error GoTo 0

     'if ProgID\CLSID default value exists
     If intErrNum2 = 0 And strValue <> "" Then

      flagFound = True  'skip remaining sections

      If IsCLSID(strValue) Then

       CLSIDPop strValue, 1, flagAllowCLSIDServer, strHive, strCLSIDVerb, _
        strCLSIDVerbValue, strCLSIDTitle

       If strCLSIDVerbValue <> "" Then

        'look for InitCmdLine value
        flagAllowICL = True  'Handler InitCmdLine is (permitted) default
        On Error Resume Next
         intErrNum6 = oReg.GetStringValue (HKLM,strKey & BS &_
          strHandlerSubKey,"InitCmdLine",strValue3)
        On Error GoTo 0

        'if ICL value found
        If intErrNum6 = 0 And strValue3 <> "" Then

         flagAllowICL = False  'since ICL was found, it may not be a default

         'if ICL is default, toggle ICL flag
         For kk = 0 To UBound(arAllowedHandlerGrammar)

          If LCase(Trim(strValue3)) = LCase(arAllowedHandlerGrammar(kk)) Then
           flagAllowICL = True : Exit For
          End If

         Next  'arAllowedHandlerGrammar member

        End If  'ICL found?

        'if three flags are all default, toggle Allow flag
        If flagAllowProvider And flagAllowCLSIDServer And _
         flagAllowICL Then flagAllow = True

        'output if required
        If Not flagAllow Or flagShowAll Then

         TitleLineWrite
         If intErrNum6 = 0 And strValue3 <> "" Then oFN.WriteLine _
          "InitCmdLine" & " = " & strValue3
         oFN.WriteLine SOCA(arHives(ii,0) & BS & strClass2Verb) &_
          "\(Default) = " & strValue
         oFN.WriteLine "  -> {" & strHive & strCTHL & strCLSIDTitle
         oFN.WriteLine Space(intCTHLS) & BS & strCLSIDVerb & "\(Default) = " &_
          strCLSIDVerbValue & CoName(IDExe(strCLSIDVerbValue))

         Exit For

        End If  'Not flagAllow?

       End If  'strCLSIDVerbValue not empty?

      End If  'IsCLSID?

     End If  'CLSID exists?

    Next  'ii hive

   End If  'ProgID & Provider values found?

  End If  'flagFound?


' CLSID
' -----

  'if Handler action not defined by InvokeProgID & InvokeVerb,
  'or by ProgID & Provider, try CLSID
  If Not flagFound Then

   strValue = ""  'intialize empty

   'look for CLSID
   On Error Resume Next
    intErrNum1 = oReg.GetStringValue (HKLM,strKey & BS & strHandlerSubKey,"CLSID",strValue)
   On Error GoTo 0

   'if CLSID value found
   If intErrNum1 = 0 And strValue <> "" Then

    'intialize variables & flags
    strValue3 = "" : strCLSIDVerb = "" : strCLSIDVerbValue = ""
    strCLSIDTitle = "" : strProvider = ""

    flagAllowCLSIDServer = False  'Handler CLSID Server is not permitted/default
    flagAllowProvider = True  'Handler Provider is permitted/default
    flagAllowICL = True  'Handler InitCmdLine is permitted/default
    flagAllow = False  'Handler is not permitted/default

    If IsCLSID(strValue) Then

     strSubSubTitle = strHandlerSubKey & BS & vbCRLF &_
      "CLSID" & " = " & strValue

     'look for Provider
     On Error Resume Next
      intErrNum5 = oReg.GetStringValue (HKLM,strKey & BS &_
       strHandlerSubKey,"Provider",strProvider)
     On Error GoTo 0

     'if Provider found
     If intErrNum5 = 0 And strProvider <> "" Then

       'modify SubSubTitle
      strSubSubTitle = strHandlerSubKey & BS & vbCRLF &_
       "Provider" & " = " & strProvider & vbCRLF &_
       "CLSID" & " = " & strValue

      flagAllowProvider = False  'Handler Provider is not default

      'check to see if Provider value is default
      For kk = 0 To UBound(arAllowedHandlerGrammar)

       If LCase(Trim(strProvider)) = LCase(arAllowedHandlerGrammar(kk)) Then
        flagAllowProvider = True : Exit For
       End If

      Next  'arAllowedHandlerGrammar member

     End If  'strProvider found?

     CLSIDPop strValue, 1, flagAllowCLSIDServer, strHive, strCLSIDVerb, _
      strCLSIDVerbValue, strCLSIDTitle

     If strCLSIDVerbValue <> "" Then

      'look for InitCmdLine value
      On Error Resume Next
       intErrNum6 = oReg.GetStringValue (HKLM,strKey & BS &_
        strHandlerSubKey,"InitCmdLine",strValue3)
      On Error GoTo 0

      'if ICL value found
      If intErrNum6 = 0 And strValue3 <> "" Then

       flagAllowICL = False  'since ICL was found, it may not be a default

       'if ICL is default, toggle ICL flag
       For kk = 0 To UBound(arAllowedHandlerGrammar)

        If LCase(Trim(strValue3)) = LCase(arAllowedHandlerGrammar(kk)) Then
         flagAllowICL = True : Exit For
        End If

       Next  'arAllowedHandlerGrammar member

      End If  'ICL found?

      'if all three flags are default, toggle Allow flag
      If flagAllowProvider And flagAllowCLSIDServer And flagAllowICL Then _
       flagAllow = True

      'output if required
      If Not flagAllow Or flagShowAll Then

       TitleLineWrite
       If intErrNum6 = 0 And strValue3 <> "" Then oFN.WriteLine _
        "InitCmdLine" & " = " & strValue3
       oFN.WriteLine "  -> {" & strHive & strCTHL & strCLSIDTitle
       oFN.WriteLine Space(intCTHLS) & BS & strCLSIDVerb & "\(Default) = " &_
        strCLSIDVerbValue & CoName(IDExe(strCLSIDVerbValue))

      End If  'output required?

     End If  'strCLSIDVerbValue not empty?

    End If  'CLSID?

   End If  'CLSID value found?

  End If  'flagFound?

 Next  'Handler subkey

End If  'Handler array returned?

'clean up
strTitle = "" : strSubTitle = "" : strSubSubTitle = ""
flagFound = False : flagAllow = False
ReDim arAllowedHandlerGrammar(0)

End If  'SecTest And WXP/WVA/WN7?




'#23. DESKTOP.INI in any local fixed disk directory (section skipped by default)

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'skip unless -supp or -all command line parameters used
If flagShowAll Or flagSupp Then

 Dim datDTIStart : datDTIStart = Now
 Public strDTITime

 'array of allowed CLSID DLLs
 Dim arOKDLLs : arOKDLLs = Array("shdocvw.dll", "occache.dll", _
  "mstask.dll", "cdfview.dll", "shell32.dll", "fontext.dll", _
  "mscoree.dll", "ieframe.dll")

 strTitle = "DESKTOP.INI DLL launch in local fixed drive directories:"

 'enumerate fixed disks
 Set colDisks = GetObject("winmgmts:\root\cimv2")._
  ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")

 For Each oDisk in colDisks

  'initialize DeskTop.Ini output & error arrays & counters
  ReDim arSDDTI(0) : ctrArDTI = 0
  ReDim arSDErr(0) : ctrArErr = 0

  'check for unreadable partition
  'root format: C:\
   Set oRoot = Fso.GetDrive(oDisk.DeviceID).RootFolder

  'find directories with System attribute containing DESKTOP.INI
  'with .ShellClassInfo section and CLSID statement
  'fill arSDDTI array with output & arSDErr with (permission) errors
  DirSysAtt oRoot

  'output DLL launch points if found
  If ctrArDTI > 0 Then
   TitleLineWrite
   'output array contents
   For i = 0 To UBound(arSDDTI) : oFN.WriteLine arSDDTI(i) : Next
  ElseIf flagShowAll Then
   TitleLineWrite : oFN.WriteLine vbCRLF & oRoot.Drive & " (no DLL launch points found)"
  End If

  'output errors if ShowAll
  If ctrArErr > 0 And flagShowAll Then

   strSubTitle = "Permission Errors on " & oRoot.Drive : TitleLineWrite : strOut = ""

   For i = 0 To UBound(arSDErr)

    'limit line length to 100
    If strOut <> "" Then

     If Len(strOut & arSDErr(i)) >= 100 Then
      oFN.WriteLine strOut : strOut = arSDErr(i)
     Else
      strOut = strOut & ", " & arSDErr(i)
     End If  'this error & prev errors>100?

    Else  'strOut empty

     If Len(arSDErr(i)) >= 100 Then
      oFN.WriteLine arSDErr(i)
     Else
      strOut = arSDErr(i)
     End If  'this error>100?

    End If  'strOut empty?

   Next  'arSDErr member

   'write out final error string
   If strOut <> "" Then oFN.WriteLine strOut : strOut = ""

  End If

  Set oRoot=Nothing

 Next  'disk in colDisks

 'determine -supp seconds used
 strDTITime = DateDiff("s",datDTIStart,Now) & " seconds"

 Set colDisks=Nothing
 strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

 'recover array memory
 ReDim arSDDTI(0) : ReDim arSDErr(0)

 End If  'flagShowAll Or flagSupp?

End If  'SecTest?




'#24. Startup Directories

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'All Users StartUp Folder (AUSFP title string (empty by default)
Dim flagAUSUF : flagAUSUF = False  'true if entry for AUSF loc'n in registry
Dim flagFE : flagFE = False  'true if AUSF exists

'in W98/WMe, see if local-language-specific All Users startup folder location
'appears in registry and set flag if it does
If strOS = "W98" Or strOS = "WME" Then

 'look for Common Startup value
 strKey = "Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
 On Error Resume Next
  oReg.GetStringValue HKLM,strKey,"Common Startup",strValue
 On Error GoTo 0

 'if Common Startup name exists and value not empty, toggle flag
 If Not IsNull(strValue) And strValue <> "" Then flagAUSUF = True

End If

'assign startup folder short names
If strOS = "W98" Or strOS = "WME" Then
 arSUFN = Array("Startup")
 arSUFDN = Array("Startup")
Else
 arSUFN = Array("Startup","AllUsersStartup")
 arSUFDN = Array("Startup","All Users")
End If

'form output file section title string
strLine = "Startup items in "

'in W98/WMe, omit username & "All Users" folder if absent from registry
If strOS = "W98" Or strOS = "WME" Then

 strLine = strLine & DQ & "Startup" & DQ

 If flagAUSUF Then
  strLine = strLine & " & " & DQ & "All Users" & LIP & "Startup" & DQ & " folders:"
 Else
  strLine = strLine & " folder:"
 End If

Else  'all other OS's

 strLine = strLine & DQ & Wshso.ExpandEnvironmentStrings("%USERNAME%") &_
  DQ & " & " & DQ & "All Users" & DQ & " startup folders:"
 arSUFDN(0) = Wshso.ExpandEnvironmentStrings("%USERNAME%")

End If

'if not ShowAll, show all output for startup directories
If Not flagShowAll Then strAllOutDefault = " {++}"

strTitle = strLine

'for each startup folder name
For i = 0 To 1  '0 = user folder, 1 = All Users folder

 strSubTitle = "" : flagFE = False

 'get the startup folder
 'in W98/WMe, set flagFE to False if "All Users" folder doesn't exist
 If i = 1 And (strOS = "W98" Or strOS = "WME") Then

  If flagAUSUF Then
   If Fso.FolderExists(strValue) Then
    Set oSUF = Fso.GetFolder(strValue)
    strSubTitle = oSUF.Path  & strAllOutDefault : flagFE = True
   Else
    strSubTitle = "WARNING! " & DQ & "All Users" & DQ &_
     " startup folder not found!"
    TitleLineWrite
   End If  'FolderExists?
  End If  'flagAUSUF?

 Else  'all other OS's at all times

  On Error Resume Next
   Set oSUF = Fso.GetFolder(Wshso.SpecialFolders(arSUFN(i)))
   intErrNum = Err.Number : Err.Clear
  On Error GoTo 0

  If intErrNum = 0 Then
   strSubTitle = oSUF.Path & strAllOutDefault : flagFE = True
  Else  'assign title for Startup folder not found
   If strOS = "W98" Or strOS = "WME" Then
    strSubTitle = "WARNING! " & DQ & arSUFDN(i) & DQ &_
     " folder not found!"
   Else
    strSubTitle = "WARNING! " & DQ & arSUFDN(i) & DQ &_
     " startup folder not found!"
   End If
   TitleLineWrite
  End If  'intErrNum=0?

 End If  'i=1 & W98/WME?

 'if startup folder exists
 If flagFE Then

  'for each file in the startup folder
  For Each oSUFi in oSUF.Files

   strLine = ""  'empty the line

   'treat file as a shortcut
   On Error Resume Next
    Set oSUSC = Wshso.CreateShortcut(oSUFi)
    intErrNum = Err.Number :  Err.Clear
   On Error GoTo 0

   'if file is a shortcut
   If intErrNum = 0 Then

    If LCase(Fso.GetExtensionName(oSUFi)) = "url" Then  'shortcut is URL

     'prepare the shortcut file base name and the target path & arguments
     strLine = Fso.GetBaseName (oSUFi.Path) & " -> URL shortcut to: " &_
      oSUSC.TargetPath

    Else

     'prepare the shortcut file base name and the target path & arguments
     strLine = Fso.GetBaseName (oSUFi.Path) & " -> shortcut to: " &_
      oSUSC.TargetPath

     If oSUSC.Arguments <> "" Then _
      strLine = strLine & " " & oSUSC.Arguments

     'add co-name
      strLine = strLine & CoName(IDExe(oSUSC.TargetPath))

    End If  'URL or shortcut?

   'if file is a PIF
   ElseIf LCase(Fso.GetExtensionName(oSUFi)) = "pif" Then

    'write out pif file target
    strPIFTgt = ""
    Dim oFi : Set oFi = Fso.OpenTextFile(oSUFi, 1)
    oFi.Skip(36)  'target starts after 36 bytes

     'target size is up to 63 bytes
     For ii = 1 To 63
      bin1C = oFi.Read(1)
      'end of target is single "00" byte
      If AscB(bin1C) = 0 Then Exit For
      'otherwise convert binary to ASCII and append to string
      strPIFTgt = strPIFTgt & Chr(AscB(bin1C))
     Next

    oFi.Close
    Set oFi=Nothing

    strLine = Fso.GetBaseName(oSUFi.Path) &_
     " -> PIF to: " & strPIFTgt & CoName(IDExe(strPIFTgt))

   'file is neither shortcut nor PIF
   Else

    'file is probably an executable so include an IWarn and
    ' the file name, using the full path as IDExe argument
    If LCase(Fso.GetFileName(oSUFi)) <> "desktop.ini" Then
     strLine = IWarn & oSUFi.Name & CoName(IDExe(oSUFi.Path))
     flagIWarn = True
    End If

   End If  'file is shortcut

   Set oSUSC=Nothing

   'if there's something to output
   If strLine <> "" Then

    'output the section title line if not already done
    TitleLineWrite

    'output the line
    oFN.WriteLine strLine

   End If

  Next  'file in startup folder

  Set oSUF=Nothing

  'if ShowAll
  If flagShowAll Then TitleLineWrite

 End If  'flagFE?

Next  'startup folder name

strTitle = "" : strSubTitle = "" : strSubSubTitle = "" : strWarn = ""
strAllOutDefault = ""

End If  'SecTest?




'#25. Windows Sidebar Gadgets

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

If strOS = "WVA" Or strOS = "WN7" Then

 'if not ShowAll, show all output for sidebar gadgets
 If Not flagShowAll Then strAllOutDefault = " {++}"

 strTitle = "Windows Sidebar Gadgets:" & strAllOutDefault

 Dim strSIP, strGP  'Settings.Ini Path, Gadget Path
 strSIP = Wshso.ExpandEnvironmentStrings("%USERPROFILE%") & "\AppData\Local\Microsoft\Windows Sidebar\Settings.ini"
 strSubTitle = strSIP

 If Fso.FileExists(strSIP) Then

  'open SETTINGS.INI
  Set oSCF = Fso.OpenTextFile (strSIP,1,False,-1)

  flagSection = False

  'for each line of SETTINGS.INI
  Do While Not oSCF.AtEndOfStream

   strLine = oSCF.ReadLine

   'if not a blank/comment line
   If Trim(strLine) <> "" And Left(LTrim(strLine),1) <> ";" Then

    'if inside [Section #] section
    If flagSection And Len(LTrim(strLine)) > 25 Then

     'if on path line
     If LCase(Left(LTrim(strLine),25)) = "privatesetting_gadgetname" Then

      'extract path string to right of "=" sign
      strGP = RTrim(Right(strLine,Len(strLine)-InStr(strLine,"=")))

      'output
      TitleLineWrite
      oFN.WriteLine strGP

      flagSection = False

     End If  'on path line?

    End If  'inside Section section?

    'if first 6 chars of line = [boot], then in the right section
    'so toggle flagSection to True
    If LCase(Left(LTrim(strLine),9)) = "[section " Then flagSection = True

   End If  'blank/comment line?

  Loop  'next SETTINGS.INI line

  oSCF.Close

 Else  'Settings.ini file not found

  strSubTitle = strSubTitle & " [file not found]"

 End If  'Settings.ini file exists?

 'if ShowAll
 If flagShowAll Then TitleLineWrite

End If  'WVa/Wn7?

strTitle = "" : strSubTitle = "" : strAllOutDefault = ""

End If  'SecTest?




'#26. Enabled Scheduled Tasks

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'Enabled Scheduled Tasks Directory/Folder object
Dim strESTDir, oESTFo

'if not ShowAll, show all output for enabled tasks
If Not flagShowAll Then strAllOutDefault = " {++}"

'prepare section title lines
strTitle = "Enabled Scheduled Tasks:" & strAllOutDefault
If strOS = "WVA" Or strOS = "WN7" Then _
 strTitle = "Non-disabled Scheduled Tasks:" & strAllOutDefault

If strOS <> "WVA" And strOS <> "WN7" Then

 '  Byte    Disabled  Enabled
 '00000030: #####1##  #####0##  <--

 'file in Tasks directory
 Dim oFi2

 'if the tasks directory exists in the Windows directory
 If Fso.FolderExists(Fso.GetSpecialFolder(WinFolder) & "\Tasks") Then

  'get the tasks folder
  Dim oJobF : Set oJobF = Fso.GetFolder(Fso.GetSpecialFolder(WinFolder) & "\Tasks")

  'for each file
  For Each oFi2 in oJobF.Files

   'if file in Tasks directory is a task (has a .JOB extension)
   If LCase(Fso.GetExtensionName(oFi2)) = "job" Then

    'try to open the task file
    On Error Resume Next
     Dim oJobFi : Set oJobFi = Fso.OpenTextFile(oFi2,1,False,-1)
     intErrNum = Err.Number : Err.Clear
    On Error GoTo 0

    'if file could be opened
    If intErrNum = 0 Then

     'read the file, determine enabled status, extract the executable name
     JobFileRead oFi2, oJobFi

     'close the .JOB file
     oJobFi.Close : Set oJobFi=Nothing

    Else  'file couldn't be opened

     'write titles & skip one line if not already done
     If strTitle <> "" Then
      TitleLineWrite : oFN.WriteBlankLines (1)
     End If

     'write error message
     oFN.WriteLine oFi2.Name & " -- insufficient permission to read this file!"

    End If  '.JOB file opened successfully?

   End If  '.JOB file extension selected?

  Next  'file in TASKS directory

  'if ShowAll, output title line if not already done
  If flagShowAll Then TitleLineWrite

 Else  'Tasks directory can't be found

  'write titles and error message
  TitleLineWrite : oFN.WriteBlankLines (1)
  oFN.WriteLine "WARNING! The " & strFPWF & "\Tasks directory cannot be found."

 End If  'Tasks directory exists?

 Set oJobF=Nothing

Else  'WVa/Wn7 -- Non-Disabled Scheduled Tasks

 'initialize error array & counter
 ReDim arErr(0) : ctrErr = 0 : strOut = ""

 'fill strOut with output & arErr with (permission) errors

 strESTDir = Wshso.ExpandEnvironmentStrings("%WINDIR%\system32\Tasks")

 Set oESTFo = Fso.GetFolder(strESTDir)

 'initiate recursion into ST folder to find enabled XML-format tasks
 DirEST oESTFo

 'output EST's if found
 If strOut <> "" Then
  TitleLineWrite : oFN.WriteBlankLines (1) : oFN.WriteLine strOut
 ElseIf flagShowAll Then
  TitleLineWrite : oFN.WriteBlankLines (1)
  oFN.WriteLine "(no enabled scheduled tasks found)"
 End If

 'output directory permission errors if ShowAll
 If ctrErr > 0 And flagShowAll Then

  strSubTitle = "Directory Permission Errors:" & vbCRLF
  TitleLineWrite : strOut = ""

  For i = 0 To UBound(arErr)

   'limit line length to 100
   If strOut <> "" Then

    If Len(strOut & arErr(i)) >= 100 Then
     oFN.WriteLine strOut : strOut = arErr(i)
    Else
     strOut = strOut & ", " & arErr(i)
    End If  'this error & prev errors>100?

   Else  'strOut empty

    If Len(arErr(i)) >= 100 Then
     oFN.WriteLine arErr(i)
    Else
     strOut = arErr(i)
    End If  'this error>100?

   End If  'strOut not empty?

  Next  'arErr member

  'write out final error string
  If strOut <> "" Then oFN.WriteLine strOut : strOut = ""

 End If  'show errors?

End If  'WVa/Wn7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = "" : strAllOutDefault = ""

End If  'SecTest?




'#27. Winsock2 Service Provider DLLs

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

strTitle = "Winsock2 Service Provider DLLs:"

Dim strNSCatKey  'NameSpace Catalog Key
Dim strProCatKey  'Protocol Catalog Key
Dim strNSSP  'NameSpace Service Provider
Dim arCat_Entries  '(returned) Namespace_Catalog5 & Protocol_Catalog9 subkeys arrays
Dim strCat_Entries  'arCat_Entries subkey member
Dim arCat_EntriesNSK  '(returned) Catalog_Entries/Catalog_Entries64 Numbered SubKeys array
Dim strCat_EntriesNSK  'arCat_EntriesNSK member
Dim arTSP  '(returned) Transport Service Provider array
Dim int1C  'single chr binary (integer) code

'TSP output array for numeric keys, key #, strlen of key #, work var
Dim arTSPFi(), intKN, intL, intT
'TSP output array for alpha (illegal) keys
Dim arATSPFi()
'arTSPFi is 4 x n array
ReDim arTSPFi(3,0)
ReDim arATSPFi(1,0)
'number of numbered TSP keys
Dim intNumKeys : intNumKeys = 0
intCnt = 0  'arTSPFi UBound - 1
Dim intACnt : intACnt = 0  'arATSPFi UBound - 1
'if not ShowAll, show all output
If Not flagShowAll Then strAllOutDefault = " {++}"

'HKLM\S\CCS\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\000000000001
'                                strKey |      strNSCatKey |
'                                                            arCat_Entries |
'                                                           strCat_Entries |
'                                                                          |arCat_EntriesNSK
'                                                                          |strCat_EntriesNSK

'NameSpace Providers

strKey = "System\CurrentControlSet\Services\Winsock2\Parameters"

'find name of NameSpace Catalog key
On Error Resume Next
 intErrNum1 = oReg.GetStringValue (HKLM,strKey,"Current_NameSpace_Catalog",strNSCatKey)
On Error GoTo 0

'if the Current_NameSpace_Catalog name exists And value set (exc for W2K!)
If intErrNum1 = 0 And strNSCatKey <> "" Then

 'find Current_NameSpace_Catalog subkeys
 oReg.EnumKey HKLM,strKey & BS & strNSCatKey,arCat_Entries

 If IsArray(arCat_Entries) Then

  strSubTitle = "Namespace Service Providers"

 'for each subkey
  For Each strCat_Entries in arCat_Entries

   strSubSubTitle = SYCA("HKLM\" & strKey & BS & strNSCatKey & BS & strCat_Entries & BS &_
    strAllOutDefault)

   'find NameSpace catalog entry subkeys
   oReg.EnumKey HKLM,strKey & BS & strNSCatKey & BS & strCat_Entries,arCat_EntriesNSK

   'if sub-keys exist
   If IsArray(arCat_EntriesNSK) Then

    'for each subkey
    For Each strCat_EntriesNSK in arCat_EntriesNSK

     'find LibraryPath
     On Error Resume Next
      intErrNum2 = oReg.GetStringValue (HKLM,strKey  & BS & strNSCatKey &_
       BS & strCat_Entries & BS & strCat_EntriesNSK,"LibraryPath",strNSSP)
     On Error GoTo 0

     'if the LibraryPath name exists And value set (exc for W2K!)
     If intErrNum2 = 0 And strNSSP <> "" Then

      TitleLineWrite

      oFN.WriteLine strCat_EntriesNSK & BS & "LibraryPath" & " = " &_
       strNSSP & CoName(IDExe(strNSSP))

     End If  'LibaryPath value set?

    Next  'arCat_EntriesNSK subkey

   Else  'arCat_EntriesNSK subkeys do not exist

    If flagShowAll Then
     TitleLineWrite : oFN.WriteLine "(sub-keys not found)"
    End If

   End If  'arCat_EntriesNSK subkeys exist?

  Next  'arCat_Entries subkey

 Else  'arCat_Entries subkeys do not exist

  If flagShowAll Then
   TitleLineWrite : oFN.WriteLine "(sub-keys not found)"
  End If

 End If

Else  'Current_NameSpace_Catalog value doesn't exist Or value not set

 If flagShowAll Then
  TitleLineWrite : oFN.WriteLine vbCRLF & SYCA("HKLM\" & strKey &_
   "\Current_Namespace_Catalog = (value not found)")
 End If

End If  'Current_NameSpace_Catalog value exists?

'HKLM\S\CCS\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\000000000001
'                               strKey |     strProCatKey |
'                                                           arCat_Entries |
'                                                          strCat_Entries |
'                                                                         |arCat_EntriesNSK
'                                                                         |strCat_EntriesNSK

'Transport Service Providers (Layered Service Providers = LSP's)

On Error Resume Next
 intErrNum1 = oReg.GetStringValue (HKLM,strKey,"Current_Protocol_Catalog",strProCatKey)
On Error GoTo 0

'if the Current_Protocol_Catalog name exists And value set (exc for W2K!)
If intErrNum1 = 0 And strProCatKey <> "" Then

 'find Current_Protocol_Catalog subkeys
 oReg.EnumKey HKLM,strKey & BS & strProCatKey,arCat_Entries

 If IsArray(arCat_Entries) Then

  strSubTitle = "Transport Service Providers"

 'for each subkey
  For Each strCat_Entries in arCat_Entries

   'reinitialize arTSPFi
   ReDim arTSPFi(3,0) : intCnt = 0

   strSubSubTitle = SYCA("HKLM\" & strKey & BS & strProCatKey & BS & strCat_Entries & BS &_
    strAllOutDefault)

   'find Protocol catalog entry subkeys
   oReg.EnumKey HKLM,strKey & BS & strProCatKey & BS & strCat_Entries,arCat_EntriesNSK

   'if sub-keys exist
   If IsArray(arCat_EntriesNSK) Then

    'for each subkey
    For Each strCat_EntriesNSK in arCat_EntriesNSK

     'can only take UBound if subkeys exist
     'find number of keys in array & # digits
     intNumKeys = UBound(arCat_EntriesNSK) + 1

     'determine # digits
     intL = Len(CStr(intNumKeys))

     'convert key name to integer
     On Error Resume Next
      intKN = CInt(strCat_EntriesNSK)
      intErrNum = Err.Number : Err.Clear
     On Error GoTo 0

     If intErrNum <> 0 Then intKN = -1  'key not in numeric format

      'find PackedCatalogItem
      On Error Resume Next
       intErrNum2 = oReg.GetBinaryValue (HKLM,strKey & BS & strProCatKey &_
        BS & strCat_Entries & BS & strCat_EntriesNSK,"PackedCatalogItem",arTSP)
      On Error GoTo 0

      'if the PackedCatalogItem name exists And value set (exc for W2K!)
      If intErrNum2 = 0 And IsArray(arTSP) Then

       strDLL = ""  'clear strDLL

       'reform strDLL from binary data array
       For i = 0 To UBound(arTSP)

        int1C = arTSP(i)
        'end of target is single "0" byte
        If int1C = 0 Then Exit For
        'otherwise convert binary to ASCII and append to string
        strDLL = strDLL & Chr(int1C)

       Next  'binary data array element

      'if key number numeric
      If intKN <> -1 Then

       'if file array populated
       If intCnt > 0 Then

        flagMatch = False

        'for every arTSPFi member
        For i = 0 To UBound(arTSPFi,2)

         'if array file matches DLL, store array subscript
         If arTSPFi(0,i) = strDLL Then
          flagMatch = True : intSS = i : Exit For
         End If

        Next  'arTSPFi member

        'if DLL is new
        If Not flagMatch Then

         'initialize output array for DLL
         ReDim Preserve arTSPFi(3,intCnt)
         arTSPFi(0,intCnt) = strDLL                         'FN path\file name
         arTSPFi(1,intCnt) = Right("0" & CStr(intKN),intL)  'OS output string
         arTSPFi(2,intCnt) = intKN                          'LA last added key number
         arTSPFi(3,intCnt) = intKN                          'UL upper limit key number

         'increment output array for next pass
         intCnt = intCnt + 1

        Else  'flagMatch = True

         'this key # consecutive to DLL UL
         If intKN - arTSPFi(3,intSS) = 1 Then

          'set DLL UL to this key #
          arTSPFi(3,intSS) = intKN

         Else  'this key # not consecutive to DLL UL

          'if last added = upper limit, add comma and key # for new range
          If arTSPFi(2,intSS) = arTSPFi(3,intSS) Then

           arTSPFi(1,intSS) = arTSPFi(1,intSS) & ", " &_
            Right("0" & CStr(intKN),intL)
           arTSPFi(2,intSS) = intKN
           arTSPFi(3,intSS) = intKN

          'last added < upper limit, add hyphen, upper limit, comma and
          'key # for new range
          Else  'LA <> UL

           arTSPFi(1,intSS) = arTSPFi(1,intSS) & " - " &_
            Right("0" & CStr(arTSPFi(3,intSS)),intL) & ", " &_
            Right("0" & CStr(intKN),intL)
           arTSPFi(2,intSS) = intKN
           arTSPFi(3,intSS) = intKN

          End If  'LA = UL?

         End If  'consecutive occurrence?

        End If  'flagMatch?

       Else  'intCnt = 0

        'add first DLL to array
        ReDim arTSPFi(3,intCnt)
        arTSPFi(0,intCnt) = strDLL                         'FN
        arTSPFi(1,intCnt) = Right("0" & CStr(intKN),intL)  'OS
        arTSPFi(2,intCnt) = intKN                          'LA
        arTSPFi(3,intCnt) = intKN                          'UL

        intCnt = intCnt + 1

       End If  'intCnt > 0?

      Else  'intKN not numeric

       'found bug here: arATSPFi written as "ATSPFi"
       ReDim Preserve arATSPFi(1,intACnt)
       arATSPFi(0,intACnt) = strSubKey
       arATSPFi(1,intACnt) = strDLL
       intACnt = intACnt + 1

      End If  'intKN numeric?

     End If  'PackedCatalogItem value exists?

    Next  'arCat_EntriesNSK subkey

    'output results

    'if Catalog_Entries sub-keys exist
    If intNumKeys > 0 Then

     'finalize output strings
     For i = 0 To UBound(arTSPFi,2)

      'last added < upper limit, add upper limit
      If arTSPFi(2,i) < arTSPFi(3,i) Then

       arTSPFi(1,i) = arTSPFi(1,i) & " - " & Right("0" & arTSPFi(3,i),intL)

      End If  'LA = UL?

     Next  'TSP array member

     TitleLineWrite

     'write out non-numeric sub-keys
     If intACnt > 0 Then

      For i = 0 To UBound(arATSPFi,2)

       oFN.WriteLine vbCRLF & arATSPFi(0,i) & " = " &_
        arATSPFi(1,i) & CoName(IDExe(arATSPFi(1,i))) & vbCRLF

      Next

     End If  'non-numeric sub-keys exist?

     'write out numeric sub-keys

     '0000000000##\PackedCatalogItem contains (DLL [Company Name], ##):
     '%SystemRoot%\system32\xxxxxx.dll [CN] ##-##, ##-##
     '%SystemRoot%\system32\yyyyyy.dll [CN] ##-##

     oFN.WriteLine String(12-intL,"0") &_
      String(intL,"#") & "\PackedCatalogItem (contains) DLL " &_
      "[Company Name], (at) " & String(intL,"#") & " range:"

     For i = 0 To UBound(arTSPFi,2)

      oFN.WriteLine arTSPFi(0,i) & CoName(IDExe(arTSPFi(0,i))) & ", " &_
       arTSPFi(1,i)

     Next

    Else  'intNumKeys=0 (no Catalog_Entries sub-keys)

     If flagShowAll Then
      TitleLineWrite : oFN.WriteLine "(sub-keys not found)"
     End If

    End If  'arSubKeys subkeys exist?

   Else  'arCat_EntriesNSK sub-keys do not exist

    If flagShowAll Then
     TitleLineWrite : oFN.WriteLine "(sub-keys not found)"
    End If

   End If  'arCat_EntriesNSK array exists?

  Next  'arCat_Entries member

 Else  'arCat_Entries sub-keys do not exist

  If flagShowAll Then
   TitleLineWrite : oFN.WriteLine "(sub-keys not found)"
  End If

 End If  'arCat_Entries array exists?

Else  'Current_Protocol_Catalog name doesn't exist Or value not set

  If flagShowAll Then
   TitleLineWrite : oFN.WriteLine vbCRLF & SYCA("HKLM\" & strKey &_
    "\Current_Protocol_Catalog = (value not found)")
  End If

End If  'Current_Protocol_Catalog name exists?

strTitle = "" : strSubTitle = "" : strSubSubTitle = "" : strAllOutDefault = ""

'recover array memory
ReDim arTSPFi(0) : ReDim arATSPFi(0)

End If  'SecTest?




'#28. Internet Explorer Toolbars, Explorer Bars, Extensions

'Explorer Bars is time-consuming due to need to examine all CLSIDs

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

strTitle = "Toolbars, Explorer Bars, Extensions:"

'HKCU/HKLM Explorer Bars, combined array of existing explorer bars
Dim arHKExplorerBars, arListedExplorerBars()
Dim strHKExplorerBar  'single explorer bar
'all CLSIDs, CLSID\Implemented Categories sub-keys, single CLSID, single Impl Cat sub-key
Dim arCLSIDKeys, arCLSIDImpCatSubKey, strImpCatSubKey
'count of HKCU/HKLM explorer bars needed for ReDim statement
Dim cntExplorerBars : cntExplorerBars = 0
Dim arHKExtensions  'HKCU/HKLM extension keys
Dim strHKExtension  'single extension key name
Dim strHKToolbar  'single toolbar value name
Dim arHKCUTbSK  'HKCU toolbar sub-keys
Dim strSKName  'single toolbar subkey name
Dim arSKValName  'toolbar sub-key value names
Dim arHKToolbarVals  'toolbar value names
Dim flagTBTLW : flagTBTLW = False  'toolbar title lines


'Toolbars

strSubTitle = "Toolbars"

Dim arAllowedToolbars(4)  'allowed toolbars must be in upper case!
arAllowedToolbars(0) = "{01E04581-4EEE-11D0-BFE9-00AA005B4383}"  '&Address
arAllowedToolbars(1) = "{0E5CBF21-D15F-11D0-8301-00AA005B4383}"  '&Links
arAllowedToolbars(2) = "{1E796980-9CC5-11D1-A83F-00C04FC99D61}"  'displayed toolbar buttons (non-CLSID)
arAllowedToolbars(3) = "{710EB7A1-45ED-11D0-924A-0020AFC7AC4D}"  'unknown default (non-CLSID)
arAllowedToolbars(4) = "{8E718888-423F-11D2-876E-00A0C9082467}"  '... &Radio

arKeys = Array("Software\Microsoft\Internet Explorer\Toolbar")

If intBits = 64 Then

arKeys = Array("Software\Microsoft\Internet Explorer\Toolbar", _
 "Software\Wow6432Node\Microsoft\Internet Explorer\Toolbar")

End If

'for each arKey
For intKey = 0 To UBound(arKeys)

 'for HKCU & HKLM hives
 For i = 0 To 1

  strSubSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

  'get toolbar key values
  oReg.EnumValues arHives(i,1),arKeys(intKey),arHKToolbarVals,arType

  'if values exist
  If IsArray(arHKToolbarVals) Then

   'for each value
   For Each strCLSID in arHKToolbarVals

    'change to UCase
    strCLSID = Trim(UCase(strCLSID))

    'assume not on allowed list
    flagAllow = False

    'is Toolbar on allowed list?
    For j = 0 To UBound(arAllowedToolbars)
     If arAllowedToolbars(j) = UCase(strCLSID) Then
      flagAllow = True : Exit For  'toggle allowed flag
     End If
    Next

    'if not allowed Or ShowAll
    If Not flagAllow Or flagShowAll Then

     flagTitle = False

     CLSIDLocTitle arHives(i,1), arKeys(intKey), strCLSID, strLocTitle

     For ctrCH = intCLL To 1

      flagWOW = False
      If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True

      ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

      If strIPSDLL <> "" Then  'IPS exists?

       If Not flagTitle Then

        'output toolbar CLSID value name
        If strSubSubTitle <> "" Then
         TitleLineWrite : oFN.WriteLine strCLSID & " = " & strLocTitle
        Else
         oFN.WriteLine vbCRLF & strCLSID & " = " & strLocTitle
        End If

        flagTitle = True

       End If

       strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
       If flagWOW Then
        strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
       End If

       'output InProcServer32 value
       oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
        strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
        strIPSDLL & CoName(IDExe(strIPSDLL))

      End If  'strIPSDLL <> ""?

     Next  'CLSID hive

    End If  'flagAllow Or ShowAll?

   Next  'HKCU/HKLM toolbar key value

  End If  'toolbar key has values

  'for HKCU Toolbar key only
  If arHives(i,0) = "HKCU" Then

   'get HKCU toolbar subkeys
   oReg.EnumKey HKCU,arKeys(intKey),arHKCUTbSK

   'if key array exists
   If IsArray(arHKCUTbSK) Then

    'for each sub-key
    For Each strSKName in arHKCUTbSK

     strSubSubTitle = "HKCU\" & arKeys(intKey) & BS & strSKName & BS

     'if one of three targeted sub-keys
     If LCase(strSKName) = "explorer" Or LCase(strSKName) = "shellbrowser" Or _
      LCase(strSKName) = "webbrowser" Then

      'get toolbar subkey values
      oReg.EnumValues HKCU,arKeys(intKey) & BS & strSKName,arSKValName,arType

      'if array of values exists
      If IsArray(arSKValName) Then

       'for each value
       For Each strValue in arSKValName

        'assume not on allowed list
        flagAllow = False

        'is Toolbar on allowed list?
        For j = 0 To UBound(arAllowedToolbars)
         If arAllowedToolbars(j) = UCase(strValue) Then
          flagAllow = True : Exit For  'toggle allowed flag
         End If
        Next

        'if not allowed Or ShowAll
        If Not flagAllow Or flagShowAll Then

         flagTitle = False

         For ctrCH = intCLL To 1

          flagWOW = False
          If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True

          ResolveCLSID strValue, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

          'if InProcServer32 value exists
          If strIPSDLL <> "" Then

           'output toolbar CLSID
           If strSubSubTitle <> "" Then TitleLineWrite
           If Not flagTitle Then
            oFN.WriteLine vbCRLF & strValue : flagTitle = True
           End If

           strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
           If flagWOW Then
            strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
           End If

           oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
            strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
            strIPSDLL & CoName(IDExe(strIPSDLL))

          End If  'IPS exists?

         Next

        End If  'flagAllow Or ShowAll?

       Next  'strValue

      End If  'IsArray(arSKValName)?

     End If  'targeted sub-key

    Next  'toolbar sub-key

   End If  'toolbar sub-key array exists

  End If  'HKCU hive?

  'if ShowAll, output title lines if not already done
  If flagShowAll Then TitleLineWrite

 Next  'hive

Next  'arKeys member




'Explorer Bars

strSubTitle = "Explorer Bars"

Dim arAllowedExplorerBars(10)  'allowed explorer bars must be in upper case!
arAllowedExplorerBars(0)  = "{30D02401-6A81-11D0-8274-00C04FD5AE38}"  'Search Band
arAllowedExplorerBars(1)  = "{32683183-48A0-441B-A342-7C2A440A9478}"  'Media Band
arAllowedExplorerBars(2)  = "{4D5C8C25-D075-11D0-B416-00C04FB90376}"  '&Tip of the Day
arAllowedExplorerBars(3)  = "{BDEADE7F-C265-11D0-BCED-00A0C90AB50F}"  '&Discuss
arAllowedExplorerBars(4)  = "{C4EE31F3-4768-11D2-BE5C-00A0C9A83DA1}"  'File and Folders Search ActiveX Control
arAllowedExplorerBars(5)  = "{EFA24E61-B078-11D0-89E4-00C04FC9E26E}"  'Favorites Band
arAllowedExplorerBars(6)  = "{EFA24E62-B078-11D0-89E4-00C04FC9E26E}"  'History Band
arAllowedExplorerBars(7)  = "{EFA24E64-B078-11D0-89E4-00C04FC9E26E}"  'Explorer Band
arAllowedExplorerBars(8)  = "{21569614-B795-46B1-85F4-E737A8DC09AD}"  'Search Band (WVa)
arAllowedExplorerBars(9)  = "{5D60981B-2654-09E1-085A-6B546CA52169}"  'Favories Band (W98)
arAllowedExplorerBars(10) = "{EFA24E63-B078-11D0-89E4-00C04FC9E26E}"  'Channels Band (NT4S)

arKeys = Array("Software\Microsoft\Internet Explorer\Explorer Bars")

If intBits = 64 Then

arKeys = Array("Software\Microsoft\Internet Explorer\Explorer Bars", _
 "Software\Wow6432Node\Microsoft\Internet Explorer\Explorer Bars")

End If

'for each arKey
For intKey = 0 To UBound(arKeys)

 'for HKCU & HKLM hives
 For i = 0 To 1

  strSubSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

  'get explorer bar subkeys
  oReg.EnumKey arHives(i,1),arKeys(intKey),arHKExplorerBars

  'if subkeys exist
  If IsArray(arHKExplorerBars) Then

   'for each subkey
   For Each strHKExplorerBar in arHKExplorerBars

    'convert subkey name (CLSID) to uppercase
    strHKExplorerBar= UCase(strHKExplorerBar)

    'assume not on allowed list
    flagAllow = False

    'add to ListedExplorerBars array
    ReDim Preserve arListedExplorerBars(cntExplorerBars)
    arListedExplorerBars(cntExplorerBars) = strHKExplorerBar
    cntExplorerBars = cntExplorerBars + 1  'cnt = UBound + 1

    'is Explorer Bar on allowed list?
    For j = 0 To UBound(arAllowedExplorerBars)
     If arAllowedExplorerBars(j) = UCase(strHKExplorerBar) Then
      flagAllow = True : Exit For  'toggle allowed flag
     End If
    Next

    'if not allowed Or ShowAll
    If Not flagAllow Or flagShowAll Then

     flagTitle = False

     CLSIDLocTitle arHives(i,1), arKeys(intKey), strHKExplorerBar, strLocTitle

     For ctrCH = intCLL To 1

      flagWOW = False
      If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True

      ResolveCLSID strHKExplorerBar, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

      'if InProcServer32 value exists
      If strIPSDLL <> "" Then

       'output explorer bar CLSID
       If strSubSubTitle <> "" Then TitleLineWrite

       If Not flagTitle Then
        oFN.WriteLine vbCRLF & strHKExplorerBar & "\(Default) = " & strLocTitle
        flagTitle = True
       End If

       strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
       If flagWOW Then
        strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
       End If

       'output InProcServer32 value
       oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
        strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
        strIPSDLL & CoName(IDExe(strIPSDLL))

      End If  'IPS exists?

     Next

    End If  'not on allowed list Or ShowAll

   Next  'HKCU/HKLM explorer bar subkey

  End If  'explorer bar key has subkeys

  'if ShowAll, output sub-title lines if not already done
  If flagShowAll Then TitleLineWrite

 Next  'hive

Next  'arKeys member

'check CLSIDs for Explorer Bars

Dim datDEBStart : datDEBStart = Now

arKeys = Array("Software\Classes\CLSID")

If intBits = 64 Then

arKeys = Array("Software\Classes\CLSID", _
 "Software\Classes\Wow6432Node\CLSID")

End If

'empty sub-sub-title before search for Explorer Bars in CLSIDs
strSubSubTitle = ""

'for each arKey
For intKey = 0 To UBound(arKeys)

 For ctrCH = intCLL To 1

  'get CLSIDs
  oReg.EnumKey arHives(ctrCH,1),arKeys(intKey),arCLSIDKeys

  If IsArray(arCLSIDKeys) Then

   'for each CLSID
   For Each strCLSIDKey in arCLSIDKeys

    'convert to uppercase
    strCLSIDKey = UCase(strCLSIDKey)

    'look for Implemented Categories subkeys
    intErrNum = oReg.EnumKey (arHives(ctrCH,1),arKeys(intKey) & BS & strCLSIDKey &_
     "\Implemented Categories",arCLSIDImpCatSubKey)

    'if Implemented Categories subkeys exist
    If intErrNum = 0 And IsArray(arCLSIDImpCatSubKey) Then

     'for each Implemented Categories subkey
     For Each strImpCatSubKey in arCLSIDImpCatSubKey

      'convert to uppercase
      strImpCatSubKey = UCase(strImpCatSubKey)

      'if subkey name is vertical or horizontal explorer bar
      If strImpCatSubKey = "{00021494-0000-0000-C000-000000000046}" Or _
       strImpCatSubKey = "{00021493-0000-0000-C000-000000000046}" Then

       flagFound = False  'assume CLSID is not listed in HKCU/HKLM explorer bars

       If IsArray(arListedExplorerBars) Then

        'search explorer bar array for CLSID
        For Each strArMember in arListedExplorerBars
         If strArMember = strCLSIDKey Then
          flagFound = True : Exit For
         End If
        Next

       End If  'IsArray(arListedExplorerBars)?

       'if CLSID not listed
       If Not flagFound Then

        'assume not allowed
        flagAllow = False

        'see if on allowed list
        For j = 0 To UBound(arAllowedExplorerBars)
         If arAllowedExplorerBars(j) = UCase(strCLSIDKey) Then
          flagAllow = True : Exit For
         End If
        Next

        'if not allowed Or ShowAll
        If Not flagAllow Or flagShowAll Then

         'look for InProcServer32
         On Error Resume Next
          intErrNum3 = oReg.GetExpandedStringValue(arHives(ctrCH,1), arKeys(intKey) &_
           BS & strCLSIDKey & "\InProcServer32","",strValue3)
         On Error GoTo 0

         'if InProcServer32 value exists
         If intErrNum3 = 0 And strValue3 <> "" Then

          'get CLSID title
          On Error Resume Next
           oReg.GetStringValue arHives(ctrCH,1),arKeys(intKey) &_
            BS & strCLSIDKey,"",strValue4
          On Error GoTo 0

          TitleLineWrite

          'output CLSID + title, prepare output string,
          'output Implemented Categories key, InProcServer32
          If strValue4 <> "" Then
           oFN.WriteLine vbCRLF & SOCA(arHives(ctrCH,0) & BS & arKeys(intKey)) &_
            BS & strCLSIDKey & "\(Default) = " & strValue4
          Else
           oFN.WriteLine vbCRLF & SOCA(arHives(ctrCH,0) & BS & arKeys(intKey)) &_
            BS & strCLSIDKey & "\(Default) = (title not found)"
          End If
          If Mid(strImpCatSubKey,9,1) = "3" Then
           strOut = " [vertical bar]"
          Else
           strOut = " [horizontal bar]"
          End If
          oFN.WriteLine "Implemented Categories\" & strImpCatSubKey & BS & strOut
          oFN.WriteLine "InProcServer32\(Default) = " & strvalue3 & CoName(IDExe(strValue3))

         End If  'CLSID InProcServer32 exists?

        End If  'CLSID not allowed Or ShowAll?

       End If  'CLSID not already found in HKCU/HKLM?

      End If  'strImpCatSubKey designates scroll bar?

     Next  'arCLSIDImpCatSubKey

    End If  'Implemented Categories sub-key exists?

   Next  'CLSID sub-key

  End If  'CLSID array exists?

 Next  'CLSID hive

Next  'arKeys member

'determine -supp seconds used
Dim strDEBTime : strDEBTime = DateDiff("s",datDEBStart,Now) & " seconds"




'Extensions (Tools menu items, toolbar buttons)

strSubTitle = "Extensions (Tools menu items, main toolbar menu buttons)"

Dim arAllowedExtensions(4)  'allowed extensions must be in upper case!
arAllowedExtensions(0) = "{438AFBA1-B0CB-11D2-9214-00104B3BCE5F}"  '&Document Tree
arAllowedExtensions(1) = "{B06300D0-CCDE-11D2-92D3-0000F87A4A55}"  'Add to R&estricted Zone
arAllowedExtensions(2) = "{BF80219A-CCDD-11D2-92D3-0000F87A4A55}"  'Add to Tr&usted Zone
arAllowedExtensions(3) = "{C95FE080-8F5D-11D2-A20B-00AA003C157A}"  'Show &Related Links
arAllowedExtensions(4) = "{FC09D8A3-C85A-11D2-92D0-0000F87A4A55}"  'Offline
'{FB5F1910-F110-11D2-BB9E-00C04F795683} MSN Messenger Service

arKeys = Array("Software\Microsoft\Internet Explorer\Extensions")

If intBits = 64 Then

arKeys = Array("Software\Microsoft\Internet Explorer\Extensions", _
 "Software\Wow6432Node\Microsoft\Internet Explorer\Extensions")

End If

'for each arKey
For intKey = 0 To UBound(arKeys)

 'for HKCU & HKLM hives
 For i = 0 To 1

  strSubSubTitle = SOCA(arHives(i,0) & BS & arKeys(intKey) & BS)

  'get extension subkeys
  oReg.EnumKey arHives(i,1),arKeys(intKey),arHKExtensions

  'if subkeys exist
  If IsArray(arHKExtensions) Then

   'for each subkey
   For Each strHKExtension in arHKExtensions

    If Len(strHKExtension) = 38 And Left(strHKExtension,1) = "{" And _
     Right(strHKExtension,1) = "}" Then

     'convert subkey name (CLSID) to uppercase
     strHKExtension= UCase(strHKExtension)

     'assume not on allowed list
     flagAllow = False

     'is Extension on allowed list?
     For j = 0 To UBound(arAllowedExtensions)
      If arAllowedExtensions(j) = UCase(strHKExtension) Then
       flagAllow = True : Exit For  'toggle allowed flag
      End If
     Next

     'if not allowed Or ShowAll
     If Not flagAllow Or flagShowAll Then

      If strSubSubTitle <> "" Then
       TitleLineWrite : oFN.WriteLine strHKExtension & BS
      Else
       oFN.WriteLine vbCRLF & strHKExtension & BS
      End If

      'look for ButtonText/MenuText/CLSIDExtension/Script/Exec/BandCLSID values
      'most output is optional (on error, do nothing)
      On Error Resume Next

       'ButtonText
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) & BS &_
        strHKExtension,"ButtonText",strValue)

       If intErrNum = 0 And strValue <> "" Then _
        oFN.WriteLine "ButtonText" & " = " & strValue

       'MenuText
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) & BS &_
        strHKExtension,"MenuText",strValue)

       If intErrNum = 0 And strValue <> "" Then _
        oFN.WriteLine "MenuText" & " = " & strValue

       'CLSIDExtension
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) & BS &_
        strHKExtension,"CLSIDExtension",strValue)

       If intErrNum = 0 And strValue <> "" Then

        flagTitle = False
        For ctrCH = intCLL To 1

         flagWOW = False
         If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True

         ResolveCLSID strValue, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

         If Not flagTitle Then
          oFN.WriteLine "CLSIDExtension" & " = " & strValue
          flagTitle = True
         End If

         strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
         If flagWOW Then
          strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
         End If

         If strIPSDLL <> "" Then
          oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
           strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
           strIPSDLL & CoName(IDExe(strIPSDLL))
         End If

        Next  'CLSID hive

       End If  'CLSIDExtension value exists

       'Script
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) &_
        BS & strHKExtension,"Script",strValue)

       If intErrNum = 0 And strValue <> "" Then oFN.WriteLine _
        "Script" & " = " & strValue & CoName(IDExe(strValue))

       'Exec
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) &_
        BS & strHKExtension,"Exec",strValue)

       If intErrNum = 0 And strValue <> "" Then oFN.WriteLine _
        "Exec" & " = " & strValue & CoName(IDExe(strValue))

       'BandCLSID
       Err.Clear
       intErrNum = oReg.GetStringValue(arHives(i,1),arKeys(intKey) &_
        BS & strHKExtension,"BandCLSID",strValue)

       If intErrNum = 0 And strValue <> "" Then

        flagTitle = False
        For ctrCH = intCLL To 1

         flagWOW = False
         If InStr(UCase(arKeys(intKey)),"WOW") > 0 Then flagWOW = True

         ResolveCLSID strValue, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

         If Not flagTitle Then
          oFN.WriteLine "BandCLSID" & " = " & strValue
          flagTitle = True
         End If

         strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
         If flagWOW Then
          strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
         End If

         If strIPSDLL <> "" Then
          oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
           strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
           strIPSDLL & CoName(IDExe(strIPSDLL))
         End If

        Next  'CLSID hive

       End If  'BandCLSID value exists

       Err.Clear

      On Error GoTo 0

     End If  'flagAllow Or flagAll?

    End If  'CLSID format?

   Next  'Extension subkey

  End If  'Extension subkeys exist

  'if ShowAll, output sub-title lines if not already done
  If flagShowAll Then TitleLineWrite

 Next  'hive

Next  'arKeys member

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arListedExplorerBars(0)

End If  'SecTest?




'#29. Internet Explorer URL Prefixes

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

strTitle = "Internet Explorer Address Prefixes:"

'prefix used if bare domain ("microsoft.com") entered into IE address box
strKey = "Software\Microsoft\Windows\CurrentVersion\URL"

strSubTitle = "Prefix for bare domain (" & DQ &_
 "domain-name-here.com" & DQ & ")" & vbCRLF & vbCRLF &_
 SOCA("HKLM\" & strKey & "\Default Prefix\")

'get DefaultPrefix default value
On Error Resume Next
 intErrNum = oReg.GetStringValue (HKLM,strKey & "\DefaultPrefix","",strValue)
On Error GoTo 0

'assume not infected
strWarn = ""

'value exists and is not empty
If intErrNum = 0 And strValue <> "" Then

 'if default value not OK, toggle warning & flagHWarn
 If Trim(LCase(strValue)) <> "http://" Then
  strWarn = HWarn : flagHWarn = True
 End If

 If strWarn <> "" Or flagShowAll Then

  TitleLineWrite : oFN.Writeline strWarn & "(Default) = " & strValue

 End If

Else  'value doesn't exist

 If flagShowAll Then
  TitleLineWrite
  oFN.WriteLine "(Default) = (value not set)"
 End If

End If  'default value exists?


'prefix used with specific service
'2 x 5 array
Dim arPrefix(1,4)
arPrefix(0,0) = "ftp" : arPrefix(1,0) = "ftp://"
arPrefix(0,1) = "gopher" : arPrefix(1,1) = "gopher://"
arPrefix(0,2) = "home" : arPrefix(1,2) = "http://"
arPrefix(0,3) = "mosaic" : arPrefix(1,3) = "http://"
arPrefix(0,4) = "www" : arPrefix(1,4) = "http://"

'find all the names in the key
oReg.EnumValues HKLM, strKey & "\Prefixes", arNames, arType

strSubTitle = "Prefix for specific service (i.e., " & DQ & "www" &_
 DQ & ")" & vbCRLF & vbCRLF & SOCA("HKLM\" & strKey & "\Prefixes\")

'enumerate data if present
If IsArray(arNames) Then

 'for each name
 For Each strName in arNames

  'assume infected
  flagMatch = False : strWarn = HWarn

  'for each prefix type
  For i = 0 To UBound(arPrefix,2)

   'if name = prefix Or name = prefix.
   If Trim(LCase(strName)) = arPrefix(0,i) Or _
    Trim(LCase(strName)) = arPrefix(0,i) & "." Then

    'get value
    On Error Resume Next
     intErrNum2 = oReg.GetStringValue(HKLM,strKey & "\Prefixes", _
      strName,strValue)
    On Error GoTo 0

    'if value exists (exc. for W2K!)
    If intErrNum2 = 0 And strValue <> "" Then

     'toggle flags if value = default value
     If Trim(LCase(strValue)) = arPrefix(1,i) Then
      flagMatch = True : strWarn = "" : Exit For
     End If  'value = arPrefix member?

    End If  'strValue exists And not empty?

   End If  'name = arPrefix member?

  Next  'arPrefix member

  'get value if name not in arPrefix
  On Error Resume Next
   If Not flagMatch Then oReg.GetStringValue HKLM, strKey & "\Prefixes",strName,strValue
  On Error GoTo 0

  'output if flagMatch Or flagShowAll
  If Not flagMatch Or flagShowAll Then

   TitleLineWrite

   If strWarn <> "" Then flagHWarn = True

    'output warning, name, value
    oFN.WriteLine strWarn & strName & " = " & strValue

  End If  'flagMatch or flagShowAll?

 Next  'prefix key name array member

 If strSubTitle <> "" And flagShowAll Then
  TitleLineWrite : oFN.WriteLine "(values not found)"
 End If

Else  'prefix key name array doesn't exist

 If flagShowAll Then
  TitleLineWrite : oFN.WriteLine "(values not found)"
 End If

End If  'prefix key name array exists

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#30. Misc. IE Hijack Points

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'IERESET Text File, IERESET file name, INF-file section name,
'array of count of missing phrase lines by section
Dim oIERTF, strSection, arSectionCount(), intTFF
Dim intAsc1Chr, intAsc2Chr  'ASCII code of 1st & 2nd chr of IERESET.INF
'zero-based number of sections in phrase array with lines missing from disk file
Public intSectionCount : intSectionCount = -1
'one-based number of lines in each section of phrase array with lines missing from disk file
Public intSectionLineCount : intSectionLineCount = 0

strTitle = "Miscellaneous IE Hijack Points"
strWarn = HWarn

'parse IERESET.INF, look for added and missing lines
Dim strIERFN : strIERFN = UCase(strFPWF) & "\INF\IERESET.INF"

'read the IE version from the registry

'IE version reg value, work string
Dim strIELVer, strIELVWK
'short string version, non-numeric if dec symbol not "."
Dim strIEShVer : strIEShVer = "0"
'numeric IE version: 0 if IE version not in registry or value not set
'otherwise, number using single local dec symbol
Dim intIELVer : intIELVer = 0
Dim strDecSym : strDecSym = "."  'dec symbol

strKey = "Software\Microsoft\Internet Explorer"
On Error Resume Next
 intErrNum = oReg.GetStringValue(HKLM,strKey,"Version",strIELVer)
On Error GoTo 0

strSubTitle = SOCA("HKLM\" & strKey & "\Version = " & strIELVer)
strSubSubTitle = strIERFN & " (used to " & DQ & "Reset Web " &_
 "Settings" & DQ & ")"

'in W2K, if value not set, strIELVer will be garbage
If intErrNum = 0 And Len(Trim(strIELVer)) > 3 Then

 'read the decimal symbol from the registry
 strKey1 = "Control Panel\International"
 On Error Resume Next
  intErrNum1 = oReg.GetStringValue(HKCU,strKey1,"sDecimal",strValue1)
 'if the symbol exists, store it
 On Error GoTo 0
 If intErrNum1 = 0 And strValue1 <> "" Then strDecSym = strValue1

 'replace 1st dec pt in the IE ver with XXX
 strIELVWK = Replace (Trim(strIELVer),".","XXX",1,1,1)
 'delete all succeeding dec pts
 strIELVWK = Replace (Trim(strIELVWK),".","",1,-1,1)
 'restore dec symbol to pos'n of first dec pt and call it an integer
 intIELVer = Replace (Trim(strIELVWK),"XXX",strDecSym,1,1,1)

 If IsNumeric(intIELVer) Then  'should exclude W2K value not set garbage

  strIEShVer = Left(LTrim(strIELVer),3)

  If strIEShVer <> "5.5" Then  'for 5.5, retain 3 chrs

    'use left-most chr
    strIEShVer = Left(LTrim(strIELVer),1)

   'if IE ver < 5, advise that INF file doesn't exist
   If intIELVer < 5 Then
    TitleLineWrite
    oFN.WriteLine vbCRLF & "IERESET.INF does not exist for this Internet " &_
     "Explorer version."
   End If  'intIELVer<5?

  End If  'strIEShVer=5.5?

 Else  'intIELVer not numeric, so advise about bad IE version and reset to 0

  strSubTitle = "HKLM\" & strKey & "\Version = (invalid data)" &_
    vbCRLF & "The Internet Explorer version cannot be found!"
  TitleLineWrite
  oFN.WriteLine "The contents of IERESET.INF cannot be reliably checked!"
  intIELVer = 0

 End If  'intIELVer numeric?

Else  'IE ver not found or value corrupt

 strSubTitle = SOCA("HKLM\" & strKey & "\Version = (invalid data)" &_
  vbCRLF & "The Internet Explorer version cannot be found!")
 TitleLineWrite
 oFN.WriteLine "The contents of IERESET.INF cannot be reliably checked!"

End If  'IE ver exists?

'change titles if not already written
If strTitle <> "" Then
 strSubTitle = strIERFN & " (used to " & DQ & "Reset Web Settings" &_
  DQ & ")"
 strSubSubTitle = ""
End If

If strIEShVer < "7" Then

 Dim arIER(31,2)  'common IERESET.INF lines & phrases; section, phrase, found-in-file-on-disk?
 arIER(0,0)="[Version]" : arIER(0,1)="Signature=""$CHICAGO$"""
 arIER(1,0)="[Version]" : arIER(1,1)="AdvancedINF=2.5,""You need a new version of advpack.dll"""
 arIER(2,0)="[RestoreHomePage]" : arIER(2,1)="AddReg=RestoreHomePage.reg"
 arIER(3,0)="[RestoreHomePage.reg]" : arIER(3,1)="HKCU,""Software\Microsoft\Internet Explorer\Main"",""Start Page"",0,%START_PAGE_URL%"
 arIER(4,0)="[RestoreBrowserSettings.reg]" : arIER(4,1)="HKLM,""Software\Microsoft\Internet Explorer\Main"",""Default_Page_URL"",0,%START_PAGE_URL%"
 arIER(5,0)="[RestoreBrowserSettings.reg]" : arIER(5,1)="HKLM,""Software\Microsoft\Internet Explorer\Main"",""Default_Search_URL"",0,%SEARCH_PAGE_URL%"
 arIER(6,0)="[RestoreBrowserSettings.reg]" : arIER(6,1)="HKLM,""Software\Microsoft\Internet Explorer\Main"",""Search Page"",0,%SEARCH_PAGE_URL%"
 arIER(7,0)="[RestoreBrowserSettings.reg]" : arIER(7,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""1"",0,""www.%s.com"""
 arIER(8,0)="[RestoreBrowserSettings.reg]" : arIER(8,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""2"",0,""www.%s.org"""
 arIER(9,0)="[RestoreBrowserSettings.reg]" : arIER(9,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""3"",0,""www.%s.net"""
 arIER(10,0)="[RestoreBrowserSettings.reg]" : arIER(10,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""4"",0,""www.%s.edu"""
 arIER(11,0)="[RestoreBrowserSettings.reg]" : arIER(11,1)="HKCU,""Software\Microsoft\Internet Explorer\Main"",""Search Page"",0,%SEARCH_PAGE_URL%"
 arIER(12,0)="[RestoreBrowserSettings.reg]" : arIER(12,1)="HKCU,""Software\Microsoft\Internet Explorer\SearchUrl"",""Provider"",0,"""""
 arIER(13,0)="[RestoreBrowserSettings.reg]" : arIER(13,1)="HKLM,""Software\Microsoft\Internet Explorer\Search"",""SearchAssistant"",0,""http://ie.search.msn.com/{SUB_RFC1766}/srchasst/srchasst.htm"""
 arIER(14,0)="[RestoreBrowserSettings.reg]" : arIER(14,1)="HKLM,""Software\Microsoft\Internet Explorer\Search"",""CustomizeSearch"",0,""http://ie.search.msn.com/{SUB_RFC1766}/srchasst/srchcust.htm"""
 arIER(15,0)="[RestoreBrowserSettings.reg]" : arIER(15,1)="HKLM,""Software\Microsoft\Windows\CurrentVersion\Internet Settings\SafeSites"",%SAFESITE_VALUE%,0,""http://ie.search.msn.com/*"""
 arIER(16,0)="[DeleteTemplates.reg]" : arIER(16,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""5"""
 arIER(17,0)="[DeleteTemplates.reg]" : arIER(17,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""6"""
 arIER(18,0)="[DeleteTemplates.reg]" : arIER(18,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""7"""
 arIER(19,0)="[DeleteTemplates.reg]" : arIER(19,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""8"""
 arIER(20,0)="[DeleteTemplates.reg]" : arIER(20,1)="HKLM,""Software\Microsoft\Internet Explorer\Main\UrlTemplate"",""9"""
 arIER(21,0)="[DeleteAutosearch.reg]" : arIER(21,1)="HKCU,""Software\Microsoft\Internet Explorer\Main"",""AutoSearch"""
 arIER(22,0)="[Strings]" : arIER(22,1)="SEARCH_PAGE_URL=""http://www.microsoft.com/isapi/redir.dll?prd=ie&ar=iesearch"""
 arIER(23,0)="[RestoreBrowserSettings]" : arIER(23,1)="AddReg=RestoreBrowserSettings.reg"

 arIER(24,0)="[RestoreBrowserSettings]" : arIER(24,1)="DelReg=DeleteTemplates.reg"
 arIER(25,0)="[RestoreBrowserSettings]" : arIER(25,1)="DelReg=DeleteTemplates.reg, DeleteAutosearch.reg"
 arIER(26,0)="[Strings]" : arIER(26,1)="START_PAGE_URL=""http://www.microsoft.com/isapi/redir.dll?prd=ie&pver=" & strIEShVer & "&ar=msnhome"""
 arIER(27,0)="[Strings]" : arIER(27,1)="START_PAGE_URL=""http://www.msn.com"""
 arIER(28,0)="[Strings]" : arIER(28,1)="SAFESITE_VALUE=""http://home.microsoft.com/"""
 arIER(29,0)="[Strings]" : arIER(29,1)="SAFESITE_VALUE=""ie.search.msn.com"""
 arIER(30,0)="[Strings]" : arIER(30,1)="MS_START_PAGE_URL=""http://www.microsoft.com/isapi/redir.dll?prd=ie&pver=" & strIEShVer & "&ar=msnhome"""
 arIER(31,0)="[Strings]" : arIER(31,1)="MS_START_PAGE_URL=""http://www.msn.com"""

 'set found-in-file-on-disk flag to False
 For i = 0 To UBound(arIER,1) : arIER(i,2) = False : Next

 'if IERESET.INF exists
 If Fso.FileExists(strIERFN) Then

  'open the file for reading/don't create/ASCII format
  Set oIERTF = Fso.OpenTextFile (strIERFN,1,False,0)

  'get the file size
  Dim intFileSize : intFileSize = Fso.GetFile(strIERFN).Size

  If intFileSize > 100 Then

   'read 1st 2 chrs, find Asc code (not AscW code)
   intAsc1Chr = Asc(oIERTF.Read(1)) : intAsc2Chr = Asc(oIERTF.Read(1))

   oIERTF.Close

   'if Asc codes = 255 & 254, file is Unicode
   'ASCII file read as Unicode: 1st Unicode line is entire file
   'Unicode file read as ASCII: 1st ASCII line is variable length
   'TriStateDefault appears to distinguish between ASCII & Unicode on file open
   'VBS internally allots 2 bytes per ASCII chr

   intTFF = 0  'ASCII fmt
   If intAsc1Chr = 255 And intAsc2Chr = 254 Then intTFF = -1  'Unicode fmt

   Set oIERTF = Fso.OpenTextFile (strIERFN,1,False,intTFF)

   strSubSubTitle = "Added lines (compared with English-language version):"

   flagInfect = False

   'for each line
   Do Until oIERTF.AtEndOfStream

    strLine = Trim(oIERTF.ReadLine)  'read a line

    flagMatch = False  'line doesn't match phrase array

    'if line not empty And not a comment
    If Len(strLine) > 0 And Left(strLine,1) <> ";" Then

     If Left(strLine,1) = "[" Then  'if line is section title

      strSection = strLine  'save the section name

     Else  'line not a section title, so it's a data line

      For i = 0 To UBound(arIER,1)  'for every line in phrase array

       'if section's identical and phrase found in line,
       'toggle line match flag & found-in-file-on-disk flag
       If LCase(arIER(i,0)) = LCase(strSection) And _
        LCase(strLine) = LCase(arIER(i,1)) Then
        flagMatch = True : arIER(i,2) = True : Exit For
        Exit For
       End If

      Next

      If Not flagMatch Then  'if line not matched
       flagInfect = True
       TitleLineWrite
       'output section name & line
       oFN.WriteLine strSection & ": " & strLine
      End If  'line matched?

     End If  'section title line?

    End If  'data line?

   Loop  'next file line

   'close IERESET.INf
   oIERTF.Close : Set oIERTF=Nothing

   'initialize section title for phrases missing from file
   strSection = ""
   strSubSubTitle = "Missing lines (compared with English-language version):"
   flagFound = True  'False if found-in-file-on-disk = False

   For i = 0 To 23  'for single-option phrases
    If Not arIER(i,2) Then
     flagFound = False : flagInfect = True 'toggle flags
     'increment counters
     IERESETCounter strSection, arIER(i,0), arSectionCount
    End If
   Next  'single-option phrase

   'check double-option phrases
   For i = 24 To 30 Step 2
    'if neither option found-in-file-on-disk
    If Not arIER(i,2) And Not arIER(i+1,2) Then
     flagFound = False : flagInfect = True 'toggle flags
     'increment counters
     IERESETCounter strSection, arIER(i,0), arSectionCount
    End If
   Next  'double-option phrase

   If Not flagFound Then  'if lines missing

    TitleLineWrite

    'output contents of arSectionCount (section title: # missing lines)
    For i = 0 To UBound(arSectionCount,2)
     strOut = " line"
     If arSectionCount(1,i) > 1 Then strOut = " lines"
     oFN.WriteLine arSectionCount(0,i) & ": " & arSectionCount(1,i) & strOut
    Next

   End If  'lines missing?

   strSubSubTitle = ""  'reset title line (no longer needed)

   If strTitle <> "" And flagShowAll Then
    strSubTitle = strIERFN & " (used to " & DQ &_
     "Reset Web Settings" & DQ & " -- no anomalies found)"
    TitleLineWrite
   End If

  Else  'IERESET.INF<100 bytes

   oIERTF.Close

   'file should always exist if IE ver > 5 Or if in one of these OS's
   If intIELVer > 5 Or strOS = "WXP" Or strOS = "W2K" Or strOS = "WME" Then

     TitleLineWrite
     oFN.WriteLine strWarn & strIERFN & " is *much* too small and is " &_
      "probably corrupt!"
     flagHWarn = True

   End If  'should file exist?

  End If  'IERSET.INF>100 bytes?

 Else  'IERESET.INF not found

  'file should always exist if IE ver > 5 Or if in one of these OS's
  If intIELVer > 5 Or strOS = "WXP" Or strOS = "W2K" Or strOS = "WME" Then

    TitleLineWrite
    oFN.WriteLine strWarn & strIERFN & " was not found!"
    flagHWarn = True

  End If  'should file exist?

 End If  'IERESET.INF found?

End If  'strIEShVer<>7?


'URLSearchHooks
strKey = "Software\Microsoft\Internet Explorer\URLSearchHooks"
strSubTitle = "HKCU\" & strKey & BS

intErrNum = oReg.EnumValues (HKCU, strKey, arNames, arType)

If IsArray(arNames) Then

 For Each strCLSID In arNames

  If UCase(strCLSID) <> "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}" Or _
   flagShowAll Then

   flagTitle = False

   CLSIDLocTitle HKCU, strKey, strCLSID, strLocTitle

   For ctrCH = intCLL To 1

    flagWOW = False
    ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

    If strIPSDLL <> "" Then

     strWarn = ""
     If UCase(strCLSID) <> "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}" Then
      strWarn = HWarn : flagHWarn = True
     End If

     TitleLineWrite

     If Not flagTitle Then
      oFN.WriteLine strWarn & strCLSID & " = " & strLocTitle
      flagTitle = True
     End If

     strCTHL = LIP & "CLSID} = " : intCTHLS = intCS

     oFN.WriteLine "  -> {" & arHives(ctrCH,0) & strCTHL &_
      strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
      strIPSDLL & CoName(IDExe(strIPSDLL))

    End If  'IPS exists?

   Next  'CLSID hive

  End If  'match Or flagShowAll?

 Next  'strCLSID

Else

 If flagShowAll Then
  TitleLineWrite
  oFN.WriteLine "(URLSearchHooks key not found!)"
 End If

End If  'IsArray?


'AboutURLs
strKey = "Software\Microsoft\Internet Explorer\AboutURLs"
strSubTitle = SOCA("HKLM\" & strKey & BS)

EnumNT HKLM, strKey, arNames, arType

If flagNames Then  'name/value pairs exist

 Set arSK = CreateObject("Scripting.Dictionary")  'key, item

 'add dictionary pairs (universal elements)
 arSK.Add "blank", "res://mshtml.dll/blank.htm"
 arSK.Add "Home", "dword:0x0000010E"
 arSK.Add "mozilla", "res://mshtml.dll/about.moz"

 'value not set or IE 5-7
 If intIELVer >= 7 Then  'IE 7+
  arSK.Add "DesktopItemNavigationFailure", "res://ieframe.dll/navcancl.htm"
  arSK.Add "NavigationCanceled", "res://ieframe.dll/navcancl.htm"
  arSK.Add "NavigationFailure", "res://ieframe.dll/navcancl.htm"
  arSK.Add "OfflineInformation", "res://ieframe.dll/offcancl.htm"
  arSK.Add "NoAdd-ons", "res://ieframe.dll/noaddon.htm"
  arSK.Add "NoAdd-onsInfo", "res://ieframe.dll/noaddoninfo.htm"
  arSK.Add "PostNotCached", "res://ieframe.dll/repost.htm"
  arSK.Add "SecurityRisk", "res://ieframe.dll/securityatrisk.htm"
  arSK.Add "Tabs", "res://ieframe.dll/tabswelcome.htm"
  arSK.Add "InPrivate", "res://ieframe.dll/inprivate.htm"
 ElseIf intIELVer = 0 Or intIELVer >= 5 Then
  arSK.Add "DesktopItemNavigationFailure", "res://shdoclc.dll/navcancl.htm"
  arSK.Add "NavigationCanceled", "res://shdoclc.dll/navcancl.htm"
  arSK.Add "NavigationFailure", "res://shdoclc.dll/navcancl.htm"
  arSK.Add "OfflineInformation", "res://shdoclc.dll/offcancl.htm"
  arSK.Add "PostNotCached", "res://mshtml.dll/repost.htm"
 Else  'IE < 5
  arSK.Add "DesktopItemNavigationFailure", "res://shdocvw.dll/navcancl.htm"
  arSK.Add "NavigationCanceled", "res://shdocvw.dll/navcancl.htm"
  arSK.Add "NavigationFailure", "res://shdocvw.dll/navcancl.htm"
  arSK.Add "OfflineInformation", "res://shdocvw.dll/offcancl.htm"
  arSK.Add "PostNotCached", "res://mshtml.dll/repost.htm"
 End If  'IE > 7?

 arSKk = arSK.Keys : arSKi = arSK.Items

 For i = 0 To UBound(arNames)

  strWarn = HWarn

  'use the type to find the value
  strValue = RtnValue (HKLM, strKey, arNames(i), arType(i))

  For j = 0 To arSK.Count-1

   flagFound = False

   If LCase(arNames(i)) = LCase(arSKk(j)) And _
    LCase(strValue) = LCase(arSKi(j)) Then
    flagFound = True : strWarn = "" : Exit For
   End If

  Next  'dictionary pair

  If Not flagFound Or flagShowAll Then

   TitleLineWrite
   WriteValueData arNames(i), strValue, arType(i), strWarn
   If strWarn <> "" Then flagHWarn = True

  End If

 Next  'arNames member

 arSK.RemoveAll : Set arSK=Nothing  'recover dictionary memory

Else

 If flagShowAll Then
  TitleLineWrite
  oFN.WriteLine "(AboutURLs key not found!)"
 End If

End If  'flagNames?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#31. HOSTS file

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'left-trimmed HOSTS line, IP address, HOSTS Path, tab pos'n, space pos'n
Dim strLineWk, strIP, strHP, intTabPosn, intSpacePosn
Dim intWSPosn : intWSPosn = 0  'white space posn
Dim intMapCtr : intMapCtr = 0  'map ctr
Dim intNLHMapCtr : intNLHMapCtr = 0  'non-localhost map ctr

'prepare section title
strTitle = "HOSTS file"

'determine HOSTS file location
If strOS <> "W98" And strOS <> "WME" Then

 'find HOSTS directory from registry, compare to default value
 strKey = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
 On Error Resume Next
  intErrNum = oReg.GetExpandedStringValue (HKLM,strKey,"DataBasePath",strValue)
 On Error GoTo 0

 'if registry value exists
 If intErrNum = 0 And strValue <> "" Then

  'trim it & expand path string
  strTmp = Wshso.ExpandEnvironmentStrings(Trim(strValue))
  'lop off trailing backslash
  If Right(strTmp,1) = BS Then strTmp = Left(strTmp,Len(strTmp)-1)

  'set HOSTS path from registry value
  strHP = strTmp & "\HOSTS"

  'output warning if not identical to default value
  strWarn = ""
  If LCase(strTmp) <> LCase(strFPSF) & "\drivers\etc" Then
   strWarn = HWarn : flagHWarn = True
  End If

  If LCase(strTmp) <> LCase(strFPSF) & "\drivers\etc" Or flagShowAll Then

   TitleLineWrite

   oFN.WriteLine vbCRLF & "HKLM\" & strKey & BS & vbCRLF & strWarn &_
    "DataBasePath" & " = " & strValue

  End If  'value <> default?

 Else  'registry value doesn't exist

  'set HOSTS location to default
  strHP = strFPSF & "\Drivers\Etc\HOSTS"

 End If  'HOSTS directory registry value exists?

Else  'W98/WMe

 strHP = strFPWF & "\HOSTS"

End If  'OS?

'if HOSTS exists
If Fso.FileExists(strHP) Then

 'open it for reading
 Set oSCF = Fso.OpenTextFile (strHP,1)

 Do While Not oSCF.AtEndOfStream

  'read a line
  strLine = oSCF.ReadLine
  strLineWk = Trim(strLine)  'trim the line

  'if line not CR And not a comment
  If Len(strLineWk) > 0 And InStr(1,strLineWk,"#",1) <> 1 Then

   'increment the mapped domain name count
   intMapCtr = intMapCtr + 1

   'find an interior space/tab
   intSpacePosn = InStr(1,strLineWk," ",1)
   intTabPosn = InStr(1,strLineWk,Chr(09),1)

   If intSpacePosn > 0 Then intWSPosn = intSpacePosn
   If intSpacePosn = 0 Or (intTabPosn > 0 And intTabPosn < intSpacePosn) _
    Then intWSPosn = intTabPosn

   'if a space or tab exists
   If intWSPosn > 0 Then

    'extract the IP address left of the space
    strIP = Left(strLineWk,intWSPosn-1)

    'if not localhost, increment the mapped non localhost count
    If strIP <> "127.0.0.1" And strIP <> "::1" Then
     intNLHMapCtr = intNLHMapCtr + 1 : TitleLineWrite
    End If

   End If  'line has embedded space?

  End If  'line not CR/comment?

 Loop  'read another line

 oSCF.Close : Set oSCF=Nothing

 'output if more than one IP mapped Or any IP mapped to non-localhost
 'Or ShowAll
 If (intMapCtr >= 1 And intNLHMapCtr > 0) Or flagShowAll Then

  'set up output strings

  'total number of mappings
  If intMapCtr = 0 Then  'none
   strOut1 = "maps: no domain names to IP addresses"
  ElseIf intMapCtr = 1 Then  'one
   strOut1 = "maps: 1 domain name to an IP address," & vbCRLF
  Else  '> 1
   strOut1 = "maps: " & intMapCtr &_
   " domain names to IP addresses," & vbCRLF
  End If

  'non-localhost mappings
  If intNLHMapCtr = 0 Then  'none
   If intMapCtr = 0 Then  'no maps found
    strOut2 = ""
   ElseIf intMapCtr = 1 Then  'one map found
    strOut2 = Space(6) & "and this is the localhost IP address"
   Else
    strOut2 = Space(6) & "and all are the localhost IP address"  '> 1 map found
   End If
  ElseIf intNLHMapCtr = 1 Then  'one
   strOut2 = Space(6) & "1 of the IP addresses is *not* localhost!"
  Else  '> 1
   strOut2 = Space(6) & intNLHMapCtr & " of the IP addresses are *not* localhost!"
  End If

  'output mapped & non-localhost counts
  TitleLineWrite

  oFN.WriteLine vbCRLF & strHP & vbCRLF & vbCRLF & strOut1 & strOut2

 End If  '>= 1 IP mapped And at least 1 IP mapped to non-localhost

Else  'HOSTS doesn't exist

 If flagShowAll Then

  TitleLineWrite
  'say file not found
  oFN.WriteLine vbCRLF & strHP & " (file not found)"

 End If  'flagShowAll?

End If  'HOSTS exists?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#32. Started Services

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'for NT-type OS's
If strOS <> "W98" And strOS <> "WME" Then

 'MS default services array, subscript number in MS default services array
 'CoName string, optionally quote-delimited path name
 Dim arMSSvc(), intMSSvcNo, strExeName, strPathNameOut

 'set up MS default services array for WVa/WXP/W2K/NT4/WN7
 'service name, service executable, DLL file name for svchost.exe-dependent service


 If strOS = "WXP" Then

  ReDim arMSSvc(110,2)
  arMSSvc(0,0) = "alerter" : arMSSvc(0,1) = "svchost.exe" : arMSSvc(0,2) = "alrsvc.dll"
  arMSSvc(1,0) = "alg" : arMSSvc(1,1) = "alg.exe" : arMSSvc(1,2) = ""
  arMSSvc(2,0) = "appmgmt" : arMSSvc(2,1) = "svchost.exe" : arMSSvc(2,2) = "appmgmts.dll"
  arMSSvc(3,0) = "wuauserv" : arMSSvc(3,1) = "svchost.exe" : arMSSvc(3,2) = "wuauserv.dll"
  arMSSvc(4,0) = "bits" : arMSSvc(4,1) = "svchost.exe" : arMSSvc(4,2) = "qmgr.dll"
  arMSSvc(5,0) = "clipsrv" : arMSSvc(5,1) = "clipsrv.exe" : arMSSvc(5,2) = ""
  arMSSvc(6,0) = "eventsystem" : arMSSvc(6,1) = "svchost.exe" : arMSSvc(6,2) = "es.dll"
  arMSSvc(7,0) = "comsysapp" : arMSSvc(7,1) = "dllhost.exe" : arMSSvc(7,2) = ""
  arMSSvc(8,0) = "browser" : arMSSvc(8,1) = "svchost.exe" : arMSSvc(8,2) = "browser.dll"
  arMSSvc(9,0) = "cryptsvc" : arMSSvc(9,1) = "svchost.exe" : arMSSvc(9,2) = "cryptsvc.dll"
  arMSSvc(10,0) = "dhcp" : arMSSvc(10,1) = "svchost.exe" : arMSSvc(10,2) = "dhcpcsvc.dll"
  arMSSvc(11,0) = "trkwks" : arMSSvc(11,1) = "svchost.exe" : arMSSvc(11,2) = "trkwks.dll"
  arMSSvc(12,0) = "msdtc" : arMSSvc(12,1) = "msdtc.exe" : arMSSvc(12,2) = ""
  arMSSvc(13,0) = "dnscache" : arMSSvc(13,1) = "svchost.exe" : arMSSvc(13,2) = "dnsrslvr.dll"
  arMSSvc(14,0) = "eventlog" : arMSSvc(14,1) = "services.exe" : arMSSvc(14,2) = ""
  arMSSvc(15,0) = "ersvc" : arMSSvc(15,1) = "svchost.exe" : arMSSvc(15,2) = "ersvc.dll"
  arMSSvc(16,0) = "fastuserswitchingcompatibility" : arMSSvc(16,1) = "svchost.exe" : arMSSvc(16,2) = "shsvcs.dll"
  arMSSvc(17,0) = "helpsvc" : arMSSvc(17,1) = "svchost.exe" : arMSSvc(17,2) = "pchsvc.dll"
  arMSSvc(18,0) = "hidserv" : arMSSvc(18,1) = "svchost.exe" : arMSSvc(18,2) = "hidserv.dll"
  arMSSvc(19,0) = "imapiservice" : arMSSvc(19,1) = "imapi.exe" : arMSSvc(19,2) = ""
  arMSSvc(20,0) = "iisadmin" : arMSSvc(20,1) = "inetinfo.exe" : arMSSvc(20,2) = ""
  arMSSvc(21,0) = "cisvc" : arMSSvc(21,1) = "cisvc.exe" : arMSSvc(21,2) = ""
  arMSSvc(22,0) = "sharedaccess" : arMSSvc(22,1) = "svchost.exe" : arMSSvc(22,2) = "ipnathlp.dll"
  arMSSvc(23,0) = "policyagent" : arMSSvc(23,1) = "lsass.exe" : arMSSvc(23,2) = ""
  arMSSvc(24,0) = "dmserver" : arMSSvc(24,1) = "svchost.exe" : arMSSvc(24,2) = "dmserver.dll"
  arMSSvc(25,0) = "dmadmin" : arMSSvc(25,1) = "dmadmin.exe" : arMSSvc(25,2) = ""
  arMSSvc(26,0) = "messenger" : arMSSvc(26,1) = "svchost.exe" : arMSSvc(26,2) = "msgsvc.dll"
  arMSSvc(27,0) = "swprv" : arMSSvc(27,1) = "srvhost.exe" : arMSSvc(27,2) = "swprv.dll"
  arMSSvc(28,0) = "netlogon" : arMSSvc(28,1) = "lsass.exe" : arMSSvc(28,2) = ""
  arMSSvc(29,0) = "mnmsrvc" : arMSSvc(29,1) = "mnmsrvc.exe" : arMSSvc(29,2) = ""
  arMSSvc(30,0) = "netman" : arMSSvc(30,1) = "svchost.exe" : arMSSvc(30,2) = "netman.dll"
  arMSSvc(31,0) = "netdde" : arMSSvc(31,1) = "netdde.exe" : arMSSvc(31,2) = ""
  arMSSvc(32,0) = "netddedsdm" : arMSSvc(32,1) = "netdde.exe" : arMSSvc(32,2) = ""
  arMSSvc(33,0) = "nla" : arMSSvc(33,1) = "svchost.exe" : arMSSvc(33,2) = "mswsock.dll"
  arMSSvc(34,0) = "ntlmssp" : arMSSvc(34,1) = "lsass.exe" : arMSSvc(34,2) = ""
  arMSSvc(35,0) = "sysmonlog" : arMSSvc(35,1) = "smlogsvc.exe" : arMSSvc(35,2) = ""
  arMSSvc(36,0) = "plugplay" : arMSSvc(36,1) = "services.exe" : arMSSvc(36,2) = ""
  arMSSvc(37,0) = "wmdmpmsp" : arMSSvc(37,1) = "svchost.exe" : arMSSvc(37,2) = "mspmspsv.dll"
  arMSSvc(38,0) = "spooler" : arMSSvc(38,1) = "spoolsv.exe" : arMSSvc(38,2) = ""
  arMSSvc(39,0) = "protectedstorage" : arMSSvc(39,1) = "lsass.exe" : arMSSvc(39,2) = ""
  arMSSvc(40,0) = "rsvp" : arMSSvc(40,1) = "rsvp.exe" : arMSSvc(40,2) = ""
  arMSSvc(41,0) = "rasauto" : arMSSvc(41,1) = "svchost.exe" : arMSSvc(41,2) = "rasauto.dll"
  arMSSvc(42,0) = "rasman" : arMSSvc(42,1) = "svchost.exe" : arMSSvc(42,2) = "rasmans.dll"
  arMSSvc(43,0) = "rdsessmgr" : arMSSvc(43,1) = "sessmgr.exe" : arMSSvc(43,2) = ""
  arMSSvc(44,0) = "rpcss" : arMSSvc(44,1) = "svchost.exe" : arMSSvc(44,2) = "rpcss.dll"
  arMSSvc(45,0) = "rpclocator" : arMSSvc(45,1) = "locator.exe" : arMSSvc(45,2) = ""
  arMSSvc(46,0) = "remoteregistry" : arMSSvc(46,1) = "svchost.exe" : arMSSvc(46,2) = "regsvc.dll"
  arMSSvc(47,0) = "ntmssvc" : arMSSvc(47,1) = "svchost.exe" : arMSSvc(47,2) = "ntmssvc.dll"
  arMSSvc(48,0) = "remoteaccess" : arMSSvc(48,1) = "svchost.exe" : arMSSvc(48,2) = "mprdim.dll"
  arMSSvc(49,0) = "seclogon" : arMSSvc(49,1) = "svchost.exe" : arMSSvc(49,2) = "seclogon.dll"
  arMSSvc(50,0) = "samss" : arMSSvc(50,1) = "lsass.exe" : arMSSvc(50,2) = ""
  arMSSvc(51,0) = "lanmanserver" : arMSSvc(51,1) = "svchost.exe" : arMSSvc(51,2) = "srvsvc.dll"
  arMSSvc(52,0) = "smtpsvc" : arMSSvc(52,1) = "inetinfo.exe" : arMSSvc(52,2) = ""
  arMSSvc(53,0) = "shellhwdetection" : arMSSvc(53,1) = "svchost.exe" : arMSSvc(53,2) = "shsvcs.dll"
  arMSSvc(54,0) = "scardsvr" : arMSSvc(54,1) = "scardsvr.exe" : arMSSvc(54,2) = ""
  arMSSvc(55,0) = "scarddrv" : arMSSvc(55,1) = "scardsvr.exe" : arMSSvc(55,2) = ""
  arMSSvc(56,0) = "ssdpsrv" : arMSSvc(56,1) = "svchost.exe" : arMSSvc(56,2) = "ssdpsrv.dll"
  arMSSvc(57,0) = "sens" : arMSSvc(57,1) = "svchost.exe" : arMSSvc(57,2) = "sens.dll"
  arMSSvc(58,0) = "srservice" : arMSSvc(58,1) = "svchost.exe" : arMSSvc(58,2) = "srsvc.dll"
  arMSSvc(59,0) = "schedule" : arMSSvc(59,1) = "svchost.exe" : arMSSvc(59,2) = "schedsvc.dll"
  arMSSvc(60,0) = "lmhosts" : arMSSvc(60,1) = "svchost.exe" : arMSSvc(60,2) = "lmhsvc.dll"
  arMSSvc(61,0) = "tapisrv" : arMSSvc(61,1) = "svchost.exe" : arMSSvc(61,2) = "tapisrv.dll"
  arMSSvc(62,0) = "tlntsvr" : arMSSvc(62,1) = "tlntsvr.exe" : arMSSvc(62,2) = ""
  arMSSvc(63,0) = "termservice" : arMSSvc(63,1) = "svchost.exe" : arMSSvc(63,2) = "termsrv.dll"
  arMSSvc(64,0) = "themes" : arMSSvc(64,1) = "svchost.exe" : arMSSvc(64,2) = "shsvcs.dll"
  arMSSvc(65,0) = "ups" : arMSSvc(65,1) = "ups.exe" : arMSSvc(65,2) = ""
  arMSSvc(66,0) = "upnphost" : arMSSvc(66,1) = "svchost.exe" : arMSSvc(66,2) = "upnphost.dll"
  arMSSvc(67,0) = "uploadmgr" : arMSSvc(67,1) = "svchost.exe" : arMSSvc(67,2) = "pchsvc.dll"
  arMSSvc(68,0) = "vss" : arMSSvc(68,1) = "vssvc.exe" : arMSSvc(68,2) = ""
  arMSSvc(69,0) = "webclient" : arMSSvc(69,1) = "svchost.exe" : arMSSvc(69,2) = "webclnt.dll"
  arMSSvc(70,0) = "audiosrv" : arMSSvc(70,1) = "svchost.exe" : arMSSvc(70,2) = "audiosrv.dll"
  arMSSvc(71,0) = "stisvc" : arMSSvc(71,1) = "svchost.exe" : arMSSvc(71,2) = "wiaservc.dll"
  arMSSvc(72,0) = "msiserver" : arMSSvc(72,1) = "msiexec.exe" : arMSSvc(72,2) = ""
  arMSSvc(73,0) = "winmgmt" : arMSSvc(73,1) = "svchost.exe" : arMSSvc(73,2) = "wmisvc.dll"
  arMSSvc(74,0) = "wmi" : arMSSvc(74,1) = "svchost.exe" : arMSSvc(74,2) = "advapi32.dll"
  arMSSvc(75,0) = "w32time" : arMSSvc(75,1) = "svchost.exe" : arMSSvc(75,2) = "w32time.dll"
  arMSSvc(76,0) = "wzcsvc" : arMSSvc(76,1) = "svchost.exe" : arMSSvc(76,2) = "wzcsvc.dll"
  arMSSvc(77,0) = "wmiapsrv" : arMSSvc(77,1) = "wmiapsrv.exe" : arMSSvc(77,2) = ""
  arMSSvc(78,0) = "lanmanworkstation" : arMSSvc(78,1) = "svchost.exe" : arMSSvc(78,2) = "wkssvc.dll"
  arMSSvc(79,0) = "w3svc" : arMSSvc(79,1) = "inetinfo.exe" : arMSSvc(79,2) = ""
  If intBits = 64 Then
   arMSSvc(79,1) = "svchost.exe" : arMSSvc(79,2) = "iisw3adm.dll"
  End If
  arMSSvc(80,0) = "dcomlaunch" : arMSSvc(80,1) = "svchost.exe" : arMSSvc(80,2) = "rpcss.dll"
  arMSSvc(81,0) = "irmon" : arMSSvc(81,1) = "svchost.exe" : arMSSvc(81,2) = "irmon.dll"
  arMSSvc(82,0) = "ip6fwhlp" : arMSSvc(82,1) = "svchost.exe" : arMSSvc(82,2) = "ip6fwhlp.dll"
  arMSSvc(83,0) = "wscsvc" : arMSSvc(83,1) = "svchost.exe" : arMSSvc(83,2) = "wscsvc.dll"
  arMSSvc(84,0) = "wmiapsrv" : arMSSvc(84,1) = "wmiapsrv.exe" : arMSSvc(84,2) = ""
  arMSSvc(85,0) = "httpfilter" : arMSSvc(85,1) = "svchost.exe" : arMSSvc(85,2) = "w3ssl.dll"
  If intBits = 64 Or strOSSS = "WS2K3" Then
   arMSSvc(85,1) = "lsass.exe" : arMSSvc(85,2) = ""
  End If
  arMSSvc(86,0) = "xmlprov" : arMSSvc(86,1) = "svchost.exe" : arMSSvc(86,2) = "xmlprov.dll"
  arMSSvc(87,0) = "dfs" : arMSSvc(87,1) = "dfssvc.exe" : arMSSvc(87,2) = ""
  arMSSvc(88,0) = "srvcsurg" : arMSSvc(88,1) = "srvcsurg.exe" : arMSSvc(88,2) = ""
  arMSSvc(89,0) = "appmgr" : arMSSvc(89,1) = "appmgr.exe" : arMSSvc(89,2) = ""
  arMSSvc(90,0) = "snmp" : arMSSvc(90,1) = "snmp.exe" : arMSSvc(90,2) = ""
  arMSSvc(91,0) = "elementmgr" : arMSSvc(91,1) = "elementmgr.exe" : arMSSvc(91,2) = ""
  arMSSvc(92,0) = "aelookupsvc" : arMSSvc(92,1) = "svchost.exe" : arMSSvc(92,2) = "aelupsvc.dll"
  arMSSvc(93,0) = "wecsvc" : arMSSvc(93,1) = "svchost.exe" : arMSSvc(93,2) = "wecsvc.dll"
  arMSSvc(94,0) = "winrm" : arMSSvc(94,1) = "svchost.exe" : arMSSvc(94,2) = "wsmsvc.dll"
  arMSSvc(95,0) = "WinHttpAutoProxySvc" : arMSSvc(95,1) = "svchost.exe" : arMSSvc(95,2) = "winhttp.dll"
  arMSSvc(96,0) = "EapHost" : arMSSvc(96,1) = "svchost.exe" : arMSSvc(96,2) = "eapsvc.dll"
  arMSSvc(97,0) = "hkmsvc" : arMSSvc(97,1) = "svchost.exe" : arMSSvc(97,2) = "kmsvc.dll"
  arMSSvc(98,0) = "napagent" : arMSSvc(98,1) = "svchost.exe" : arMSSvc(98,2) = "qagentrt.dll"
  arMSSvc(99,0) = "WmdmPmSN" : arMSSvc(99,1) = "svchost.exe" : arMSSvc(99,2) = "MsPMSNSv.dll"
  arMSSvc(100,0) = "idsvc" : arMSSvc(100,1) = "infocard.exe" : arMSSvc(100,2) = ""
  arMSSvc(101,0) = "WudfSvc" : arMSSvc(101,1) = "svchost.exe" : arMSSvc(101,2) = "WUDFSvc.dll"
  arMSSvc(102,0) = "WMPNetworkSvc" : arMSSvc(102,1) = "WMPNetwk.exe" : arMSSvc(102,2) = ""
  arMSSvc(103,0) = "NtFrs" : arMSSvc(103,1) = "ntfrs.exe" : arMSSvc(103,2) = ""
  arMSSvc(104,0) = "RSoPProv" : arMSSvc(104,1) = "RSoPProv.exe" : arMSSvc(104,2) = ""
  arMSSvc(105,0) = "sacsvr" : arMSSvc(105,1) = "svchost.exe" : arMSSvc(105,2) = "sacsvr.dll"
  arMSSvc(106,0) = "vds" : arMSSvc(106,1) = "vds.exe" : arMSSvc(106,2) = ""
  arMSSvc(107,0) = "UMWdf" : arMSSvc(107,1) = "wdfmgr.exe" : arMSSvc(107,2) = ""
  arMSSvc(108,0) = "IASJet" : arMSSvc(108,1) = "svchost.exe" : arMSSvc(108,2) = "iasrecst.dll"
  arMSSvc(109,0) = "Dot3svc" : arMSSvc(109,1) = "svchost.exe" : arMSSvc(109,2) = "dot3svc.dll"
  arMSSvc(110,0) = "BthServ" : arMSSvc(110,1) = "svchost.exe" : arMSSvc(110,2) = "bthserv.dll"  'Bluetooth Support Service

'  arMSSvc(111,0) = "" : arMSSvc(111,1) = "svchost.exe" : arMSSvc(111,2) = ".dll"


 ElseIf strOS = "W2K" Then

  ReDim arMSSvc(69,2)
  arMSSvc(0,0) = "alerter" : arMSSvc(0,1) = "services.exe" : arMSSvc(0,2) = ""
  arMSSvc(1,0) = "appmgmt" : arMSSvc(1,1) = "services.exe" : arMSSvc(1,2) = ""
  arMSSvc(2,0) = "wuauserv" : arMSSvc(2,1) = "svchost.exe" : arMSSvc(2,2) = "wuauserv.dll"
  arMSSvc(3,0) = "bits" : arMSSvc(3,1) = "svchost.exe" : arMSSvc(3,2) = "qmgr.dll"
  arMSSvc(4,0) = "clipsrv" : arMSSvc(4,1) = "clipsrv.exe" : arMSSvc(4,2) = ""
  arMSSvc(5,0) = "eventsystem" : arMSSvc(5,1) = "svchost.exe" : arMSSvc(5,2) = "es.dll"
  arMSSvc(6,0) = "browser" : arMSSvc(6,1) = "services.exe" : arMSSvc(6,2) = ""
  arMSSvc(7,0) = "dhcp" : arMSSvc(7,1) = "services.exe" : arMSSvc(7,2) = ""
  arMSSvc(8,0) = "trkwks" : arMSSvc(8,1) = "services.exe" : arMSSvc(8,2) = ""
  arMSSvc(9,0) = "msdtc" : arMSSvc(9,1) = "msdtc.exe" : arMSSvc(9,2) = ""
  arMSSvc(10,0) = "dnscache" : arMSSvc(10,1) = "services.exe" : arMSSvc(10,2) = ""
  arMSSvc(11,0) = "eventlog" : arMSSvc(11,1) = "services.exe" : arMSSvc(11,2) = ""
  arMSSvc(12,0) = "fax" : arMSSvc(12,1) = "faxsvc.exe" : arMSSvc(12,2) = ""
  arMSSvc(13,0) = "iisadmin" : arMSSvc(13,1) = "inetinfo.exe" : arMSSvc(13,2) = ""
  arMSSvc(14,0) = "cisvc" : arMSSvc(14,1) = "cisvc.exe" : arMSSvc(14,2) = ""
  arMSSvc(15,0) = "sharedaccess" : arMSSvc(15,1) = "svchost.exe" : arMSSvc(15,2) = "ipnathlp.dll"
  arMSSvc(16,0) = "policyagent" : arMSSvc(16,1) = "lsass.exe" : arMSSvc(16,2) = ""
  arMSSvc(17,0) = "dmserver" : arMSSvc(17,1) = "services.exe" : arMSSvc(17,2) = ""
  arMSSvc(18,0) = "dmadmin" : arMSSvc(18,1) = "dmadmin.exe" : arMSSvc(18,2) = ""
  arMSSvc(19,0) = "messenger" : arMSSvc(19,1) = "services.exe" : arMSSvc(19,2) = ""
  arMSSvc(20,0) = "netlogon" : arMSSvc(20,1) = "lsass.exe" : arMSSvc(20,2) = ""
  arMSSvc(21,0) = "mnmsrvc" : arMSSvc(21,1) = "mnmsrvc.exe" : arMSSvc(21,2) = ""
  arMSSvc(22,0) = "netman" : arMSSvc(22,1) = "svchost.exe" : arMSSvc(22,2) = "netman.dll"
  arMSSvc(23,0) = "netdde" : arMSSvc(23,1) = "netdde.exe" : arMSSvc(23,2) = ""
  arMSSvc(24,0) = "ntlmssp" : arMSSvc(24,1) = "lsass.exe" : arMSSvc(24,2) = ""
  arMSSvc(25,0) = "sysmonlog" : arMSSvc(25,1) = "smlogsvc.exe" : arMSSvc(25,2) = ""
  arMSSvc(26,0) = "plugplay" : arMSSvc(26,1) = "services.exe" : arMSSvc(26,2) = ""
  arMSSvc(27,0) = "wmdmpmsn" : arMSSvc(27,1) = "svchost.exe" : arMSSvc(27,2) = "mspmsnsv.dll"
  arMSSvc(28,0) = "spooler" : arMSSvc(28,1) = "spoolsv.exe" : arMSSvc(28,2) = ""
  arMSSvc(29,0) = "protectedstorage" : arMSSvc(29,1) = "services.exe" : arMSSvc(29,2) = ""
  arMSSvc(30,0) = "rsvp" : arMSSvc(30,1) = "rsvp.exe" : arMSSvc(30,2) = ""
  arMSSvc(31,0) = "rasauto" : arMSSvc(31,1) = "svchost.exe" : arMSSvc(31,2) = "rasauto.dll"
  arMSSvc(32,0) = "rasman" : arMSSvc(32,1) = "svchost.exe" : arMSSvc(32,2) = "rasmans.dll"
  arMSSvc(33,0) = "rpcss" : arMSSvc(33,1) = "svchost.exe" : arMSSvc(33,2) = "rpcss.dll"
  arMSSvc(34,0) = "rpclocator" : arMSSvc(34,1) = "locator.exe" : arMSSvc(34,2) = ""
  arMSSvc(35,0) = "remoteregistry" : arMSSvc(35,1) = "regsvc.exe" : arMSSvc(35,2) = ""
  arMSSvc(36,0) = "ntmssvc" : arMSSvc(36,1) = "svchost.exe" : arMSSvc(36,2) = "ntmssvc.dll"
  arMSSvc(37,0) = "remoteaccess" : arMSSvc(37,1) = "svchost.exe" : arMSSvc(37,2) = "mprdim.dll"
  arMSSvc(38,0) = "seclogon" : arMSSvc(38,1) = "services.exe" : arMSSvc(38,2) = ""
  arMSSvc(39,0) = "samss" : arMSSvc(39,1) = "lsass.exe" : arMSSvc(39,2) = ""
  arMSSvc(40,0) = "lanmanserver" : arMSSvc(40,1) = "services.exe" : arMSSvc(40,2) = ""
  arMSSvc(41,0) = "smtpsvc" : arMSSvc(41,1) = "inetinfo.exe" : arMSSvc(41,2) = ""
  arMSSvc(42,0) = "scardsvr" : arMSSvc(42,1) = "scardsvr.exe" : arMSSvc(42,2) = ""
  arMSSvc(43,0) = "scarddrv" : arMSSvc(43,1) = "scardsvr.exe" : arMSSvc(43,2) = ""
  arMSSvc(44,0) = "stisvc" : arMSSvc(44,1) = "stisvc.exe" : arMSSvc(44,2) = ""
  arMSSvc(45,0) = "sens" : arMSSvc(45,1) = "svchost.exe" : arMSSvc(45,2) = "sens.dll"
  arMSSvc(46,0) = "schedule" : arMSSvc(46,1) = "mstask.exe" : arMSSvc(46,2) = ""
  arMSSvc(47,0) = "lmhosts" : arMSSvc(47,1) = "services.exe" : arMSSvc(47,2) = ""
  arMSSvc(48,0) = "tapisrv" : arMSSvc(48,1) = "svchost.exe" : arMSSvc(48,2) = "tapisrv.dll"
  arMSSvc(49,0) = "tlntsvr" : arMSSvc(49,1) = "tlntsvr.exe" : arMSSvc(49,2) = ""
  arMSSvc(50,0) = "ups" : arMSSvc(50,1) = "ups.exe" : arMSSvc(50,2) = ""
  arMSSvc(51,0) = "msiserver" : arMSSvc(51,1) = "msiexec.exe" : arMSSvc(51,2) = ""
  arMSSvc(52,0) = "winmgmt" : arMSSvc(52,1) = "winmgmt.exe" : arMSSvc(52,2) = ""
  arMSSvc(53,0) = "wmi" : arMSSvc(53,1) = "services.exe" : arMSSvc(53,2) = ""
  arMSSvc(54,0) = "w32time" : arMSSvc(54,1) = "services.exe" : arMSSvc(54,2) = ""
  arMSSvc(55,0) = "wzcsvc" : arMSSvc(55,1) = "svchost.exe" : arMSSvc(55,2) = "wzcsvc.dll"
  arMSSvc(56,0) = "lanmanworkstation" : arMSSvc(56,1) = "services.exe" : arMSSvc(56,2) = ""
  arMSSvc(57,0) = "w3svc" : arMSSvc(57,1) = "inetinfo.exe" : arMSSvc(57,2) = ""
  arMSSvc(58,0) = "wmdm pmsp service" : arMSSvc(58,1) = "mspmspsv.exe" : arMSSvc(58,2) = ""
  arMSSvc(59,0) = "msftpsvc" : arMSSvc(59,1) = "inetinfo.exe" : arMSSvc(59,2) = ""
  arMSSvc(60,0) = "irmon" : arMSSvc(60,1) = "svchost.exe" : arMSSvc(60,2) = "irmon.dll"
  'W2KS
  arMSSvc(61,0) = "dhcpServer" : arMSSvc(61,1) = "tcpsvcs.exe" : arMSSvc(61,2) = ""
  arMSSvc(62,0) = "dfs" : arMSSvc(62,1) = "dfssvc.exe" : arMSSvc(62,2) = ""
  arMSSvc(63,0) = "dns" : arMSSvc(63,1) = "dns.exe" : arMSSvc(63,2) = ""
  arMSSvc(64,0) = "ias" : arMSSvc(64,1) = "svchost.exe" : arMSSvc(64,2) = "ias.dll"
  arMSSvc(65,0) = "licenseservice" : arMSSvc(65,1) = "llssrv.exe" : arMSSvc(65,2) = ""
  arMSSvc(66,0) = "NetDDEdsdm" : arMSSvc(66,1) = "netdde.exe" : arMSSvc(66,2) = ""
  arMSSvc(67,0) = "TrkSvr" : arMSSvc(67,1) = "services.exe" : arMSSvc(67,2) = ""
  arMSSvc(68,0) = "NtFrs" : arMSSvc(68,1) = "ntfrs.exe" : arMSSvc(68,2) = ""
  arMSSvc(69,0) = "UtilMan" : arMSSvc(69,1) = "utilman.exe" : arMSSvc(69,2) = ""

'  arMSSvc(70,0) = "" : arMSSvc(70,1) = "svchost.exe" : arMSSvc(70,2) = ".dll"


 ElseIf strOs = "NT4" Then

  ReDim arMSSvc(36,2)
  arMSSvc(0,0) = "alerter" : arMSSvc(0,1) = "services.exe" : arMSSvc(0,2) = ""
  arMSSvc(1,0) = "clipsrv" : arMSSvc(1,1) = "clipsrv.exe" : arMSSvc(1,2) = ""
  arMSSvc(2,0) = "eventsystem" : arMSSvc(2,1) = "esserver.exe" : arMSSvc(2,2) = ""
  arMSSvc(3,0) = "browser" : arMSSvc(3,1) = "services.exe" : arMSSvc(3,2) = ""
  arMSSvc(4,0) = "dhcp" : arMSSvc(4,1) = "services.exe" : arMSSvc(4,2) = ""
  arMSSvc(5,0) = "replicator" : arMSSvc(5,1) = "lmrepl.exe" : arMSSvc(5,2) = ""
  arMSSvc(6,0) = "eventlog" : arMSSvc(6,1) = "services.exe" : arMSSvc(6,2) = ""
  arMSSvc(7,0) = "messenger" : arMSSvc(7,1) = "services.exe" : arMSSvc(7,2) = ""
  arMSSvc(8,0) = "netlogon" : arMSSvc(8,1) = "lsass.exe" : arMSSvc(8,2) = ""
  arMSSvc(9,0) = "netdde" : arMSSvc(9,1) = "netdde.exe" : arMSSvc(9,2) = ""
  arMSSvc(10,0) = "netddedsdm" : arMSSvc(10,1) = "netdde.exe" : arMSSvc(10,2) = ""
  arMSSvc(11,0) = "ntlmssp" : arMSSvc(11,1) = "services.exe" : arMSSvc(11,2) = ""
  arMSSvc(12,0) = "plugplay" : arMSSvc(12,1) = "services.exe" : arMSSvc(12,2) = ""
  arMSSvc(13,0) = "protectedstorage" : arMSSvc(13,1) = "pstores.exe" : arMSSvc(13,2) = ""
  arMSSvc(14,0) = "rasauto" : arMSSvc(14,1) = "rasman.exe" : arMSSvc(14,2) = ""
  arMSSvc(15,0) = "rasman" : arMSSvc(15,1) = "rasman.exe" : arMSSvc(15,2) = ""
  arMSSvc(16,0) = "rpclocator" : arMSSvc(16,1) = "locator.exe" : arMSSvc(16,2) = ""
  arMSSvc(17,0) = "rpcss" : arMSSvc(17,1) = "rpcss.exe" : arMSSvc(17,2) = ""
  arMSSvc(18,0) = "lanmanserver" : arMSSvc(18,1) = "services.exe" : arMSSvc(18,2) = ""
  arMSSvc(19,0) = "spooler" : arMSSvc(19,1) = "spoolss.exe" : arMSSvc(19,2) = ""
  arMSSvc(20,0) = "sens" : arMSSvc(20,1) = "sens.exe" : arMSSvc(20,2) = ""
  arMSSvc(21,0) = "schedule" : arMSSvc(21,1) = "mstask.exe" : arMSSvc(21,2) = ""
  arMSSvc(22,0) = "lmhosts" : arMSSvc(22,1) = "services.exe" : arMSSvc(22,2) = ""
  arMSSvc(23,0) = "tapisrv" : arMSSvc(23,1) = "tapisrv.exe" : arMSSvc(23,2) = ""
  arMSSvc(24,0) = "ups" : arMSSvc(24,1) = "ups.exe" : arMSSvc(24,2) = ""
  arMSSvc(25,0) = "msiserver" : arMSSvc(25,1) = "msiexec.exe" : arMSSvc(25,2) = ""
  arMSSvc(26,0) = "winmgmt" : arMSSvc(26,1) = "winmgmt.exe" : arMSSvc(26,2) = ""
  arMSSvc(27,0) = "lanmanworkstation" : arMSSvc(27,1) = "services.exe" : arMSSvc(27,2) = ""
  arMSSvc(28,0) = "certsvc" : arMSSvc(28,1) = "certsrv.exe" : arMSSvc(28,2) = ""
  arMSSvc(29,0) = "cisvc" : arMSSvc(29,1) = "cisvc.exe" : arMSSvc(29,2) = ""
  arMSSvc(30,0) = "msftpsvc" : arMSSvc(30,1) = "inetinfo.exe" : arMSSvc(30,2) = ""
  arMSSvc(31,0) = "iisadmin" : arMSSvc(31,1) = "inetinfo.exe" : arMSSvc(31,2) = ""
  arMSSvc(32,0) = "licenseservice" : arMSSvc(32,1) = "llssrv.exe" : arMSSvc(32,2) = ""
  arMSSvc(33,0) = "nntpsvc" : arMSSvc(33,1) = "inetinfo.exe" : arMSSvc(33,2) = ""
  arMSSvc(34,0) = "smtpsvc" : arMSSvc(34,1) = "inetinfo.exe" : arMSSvc(34,2) = ""
  arMSSvc(35,0) = "msdtc" : arMSSvc(35,1) = "msdtc.exe" : arMSSvc(35,2) = ""
  arMSSvc(36,0) = "w3svc" : arMSSvc(36,1) = "inetinfo.exe" : arMSSvc(36,2) = ""


ElseIf strOS = "WVA" Or strOS = "WN7" Then  'WVA, WN7, WS2K8 R2, WN8, W10

  ReDim arMSSvc(184,2)  'WN7 & WS2K8 R2
  If strOS   = "WVA" Then ReDim arMSSvc(193,2)
  If strOSSS = "WN8" Then ReDim arMSSvc(187,2)
  If strOSSS = "W10" Then ReDim arMSSvc(217,2)

  arMSSvc(0,0) = "Appinfo" : arMSSvc(0,1) = "svchost.exe" : arMSSvc(0,2) = "appinfo.dll"
  arMSSvc(1,0) = "BFE" : arMSSvc(1,1) = "svchost.exe" : arMSSvc(1,2) = "bfe.dll"
  arMSSvc(2,0) = "KeyIso" : arMSSvc(2,1) = "lsass.exe" : arMSSvc(2,2) = ""
  arMSSvc(3,0) = "EventSystem" : arMSSvc(3,1) = "svchost.exe" : arMSSvc(3,2) = "es.dll"
  arMSSvc(4,0) = "Browser" : arMSSvc(4,1) = "svchost.exe" : arMSSvc(4,2) = "browser.dll"
  arMSSvc(5,0) = "CryptSvc" : arMSSvc(5,1) = "svchost.exe" : arMSSvc(5,2) = "cryptsvc.dll"
  arMSSvc(6,0) = "DcomLaunch" : arMSSvc(6,1) = "svchost.exe" : arMSSvc(6,2) = "rpcss.dll"
  arMSSvc(7,0) = "Uxsms" : arMSSvc(7,1) = "svchost.exe" : arMSSvc(7,2) = "uxsms.dll"
  arMSSvc(8,0) = "Dhcp" : arMSSvc(8,1) = "svchost.exe" : arMSSvc(8,2) = "dhcpcore.dll"
  If strOS = "WVA" Then arMSSvc(8,2) = "dhcpcsvc.dll"
  arMSSvc(9,0) = "DPS" : arMSSvc(9,1) = "svchost.exe" : arMSSvc(9,2) = "dps.dll"
  arMSSvc(10,0) = "WdiServiceHost" : arMSSvc(10,1) = "svchost.exe" : arMSSvc(10,2) = "wdi.dll"
  arMSSvc(11,0) = "TrkWks" : arMSSvc(11,1) = "svchost.exe" : arMSSvc(11,2) = "trkwks.dll"
  arMSSvc(12,0) = "Dnscache" : arMSSvc(12,1) = "svchost.exe" : arMSSvc(12,2) = "dnsrslvr.dll"
  arMSSvc(13,0) = "fdPHost" : arMSSvc(13,1) = "svchost.exe" : arMSSvc(13,2) = "fdPHost.dll"
  arMSSvc(14,0) = "FDResPub" : arMSSvc(14,1) = "svchost.exe" : arMSSvc(14,2) = "fdrespub.dll"
  arMSSvc(15,0) = "gpsvc" : arMSSvc(15,1) = "svchost.exe" : arMSSvc(15,2) = "gpsvc.dll"
  arMSSvc(16,0) = "HomeGroupListener" : arMSSvc(16,1) = "svchost.exe" : arMSSvc(16,2) = "ListSvc.dll"
  arMSSvc(17,0) = "HomeGroupProvider" : arMSSvc(17,1) = "svchost.exe" : arMSSvc(17,2) = "provsvc.dll"
  arMSSvc(18,0) = "iphlpsvc" : arMSSvc(18,1) = "svchost.exe" : arMSSvc(18,2) = "iphlpsvc.dll"
  arMSSvc(19,0) = "MMCSS" : arMSSvc(19,1) = "svchost.exe" : arMSSvc(19,2) = "mmcss.dll"
  arMSSvc(20,0) = "Netman" : arMSSvc(20,1) = "svchost.exe" : arMSSvc(20,2) = "netman.dll"
  arMSSvc(21,0) = "netprofm" : arMSSvc(21,1) = "svchost.exe" : arMSSvc(21,2) = "netprofm.dll"
  If strOSSS = "WN8" Or strOSSS = "W10" Then arMSSvc(21,2) = "netprofmsvc.dll"
  arMSSvc(22,0) = "NlaSvc" : arMSSvc(22,1) = "svchost.exe" : arMSSvc(22,2) = "nlasvc.dll"
  arMSSvc(23,0) = "nsi" : arMSSvc(23,1) = "svchost.exe" : arMSSvc(23,2) = "nsisvc.dll"
  arMSSvc(24,0) = "CscService" : arMSSvc(24,1) = "svchost.exe" : arMSSvc(24,2) = "cscsvc.dll"
  arMSSvc(25,0) = "PNRPsvc" : arMSSvc(25,1) = "svchost.exe" : arMSSvc(25,2) = "pnrpsvc.dll"
  arMSSvc(25,0) = "PNRPsvc" : arMSSvc(25,1) = "svchost.exe" : arMSSvc(25,2) = "pnrpsvc.dll"  'Peer Name Resolution Protocol Service
  If strOS = "WVA" Then arMSSvc(25,2) = "p2psvc.dll"
  arMSSvc(26,0) = "p2psvc" : arMSSvc(26,1) = "svchost.exe" : arMSSvc(26,2) = "p2psvc.dll"
  arMSSvc(27,0) = "p2pimsvc" : arMSSvc(27,1) = "svchost.exe" : arMSSvc(27,2) = "pnrpsvc.dll"
  If strOS = "WVA" Then arMSSvc(27,2) = "p2psvc.dll"
  arMSSvc(28,0) = "PlugPlay" : arMSSvc(28,1) = "svchost.exe" : arMSSvc(28,2) = "umpnpmgr.dll"
  arMSSvc(29,0) = "Power" : arMSSvc(29,1) = "svchost.exe" : arMSSvc(29,2) = "umpo.dll"
  arMSSvc(30,0) = "Spooler" : arMSSvc(30,1) = "spoolsv.exe" : arMSSvc(30,2) = ""
  arMSSvc(31,0) = "PcaSvc" : arMSSvc(31,1) = "svchost.exe" : arMSSvc(31,2) = "pcasvc.dll"
  arMSSvc(32,0) = "RpcSs" : arMSSvc(32,1) = "svchost.exe" : arMSSvc(32,2) = "rpcss.dll"
  arMSSvc(33,0) = "RpcEptMapper" : arMSSvc(33,1) = "svchost.exe" : arMSSvc(33,2) = "RpcEpMap.dll"
  arMSSvc(34,0) = "SamSs" : arMSSvc(34,1) = "lsass.exe" : arMSSvc(34,2) = ""
  arMSSvc(35,0) = "wscsvc" : arMSSvc(35,1) = "svchost.exe" : arMSSvc(35,2) = "wscsvc.dll"
  arMSSvc(36,0) = "LanmanServer" : arMSSvc(36,1) = "svchost.exe" : arMSSvc(36,2) = "srvsvc.dll"
  arMSSvc(37,0) = "ShellHWDetection" : arMSSvc(37,1) = "svchost.exe" : arMSSvc(37,2) = "shsvcs.dll"
  arMSSvc(38,0) = "SSDPSRV" : arMSSvc(38,1) = "svchost.exe" : arMSSvc(38,2) = "ssdpsrv.dll"
  arMSSvc(39,0) = "SysMain" : arMSSvc(39,1) = "svchost.exe" : arMSSvc(39,2) = "sysmain.dll"
  arMSSvc(40,0) = "SENS" : arMSSvc(40,1) = "svchost.exe" : arMSSvc(40,2) = "sens.dll"
  arMSSvc(41,0) = "Schedule" : arMSSvc(41,1) = "svchost.exe" : arMSSvc(41,2) = "schedsvc.dll"
  arMSSvc(42,0) = "lmhosts" : arMSSvc(42,1) = "svchost.exe" : arMSSvc(42,2) = "lmhsvc.dll"
  arMSSvc(43,0) = "Themes" : arMSSvc(43,1) = "svchost.exe" : arMSSvc(43,2) = "themeservice.dll"
  If strOS = "WVA" Then arMSSvc(43,2) = "shsvcs.dll"
  arMSSvc(44,0) = "upnphost" : arMSSvc(44,1) = "svchost.exe" : arMSSvc(44,2) = "upnphost.dll"
  arMSSvc(45,0) = "ProfSvc" : arMSSvc(45,1) = "svchost.exe" : arMSSvc(45,2) = "profsvc.dll"
  arMSSvc(46,0) = "Audiosrv" : arMSSvc(46,1) = "svchost.exe" : arMSSvc(46,2) = "Audiosrv.dll"
  arMSSvc(47,0) = "AudioEndpointBuilder" : arMSSvc(47,1) = "svchost.exe" : arMSSvc(47,2) = "Audiosrv.dll"
  If strOSSS = "WN8" Or strOSSS = "W10" Then arMSSvc(47,2) = "AudioEndpointBuilder.dll"
  arMSSvc(48,0) = "WinDefend" : arMSSvc(48,1) = "svchost.exe" : arMSSvc(48,2) = "mpsvc.dll"
  If strOSSS = "WN8" Or strOSSS = "W10" Then
   arMSSvc(48,1) = "MsMpEng.exe" : arMSSvc(48,2) = ""
  End If
  arMSSvc(49,0) = "eventlog" : arMSSvc(49,1) = "svchost.exe" : arMSSvc(49,2) = "wevtsvc.dll"
  arMSSvc(50,0) = "MpsSvc" : arMSSvc(50,1) = "svchost.exe" : arMSSvc(50,2) = "mpssvc.dll"
  arMSSvc(51,0) = "Winmgmt" : arMSSvc(51,1) = "svchost.exe" : arMSSvc(51,2) = "WMIsvc.dll"
  arMSSvc(52,0) = "WMPNetworkSvc" : arMSSvc(52,1) = "wmpnetwk.exe" : arMSSvc(52,2) = ""
  arMSSvc(53,0) = "WSearch" : arMSSvc(53,1) = "SearchIndexer.exe" : arMSSvc(53,2) = ""
  arMSSvc(54,0) = "wuauserv" : arMSSvc(54,1) = "svchost.exe" : arMSSvc(54,2) = "wuaueng.dll"
  arMSSvc(55,0) = "LanmanWorkstation" : arMSSvc(55,1) = "svchost.exe" : arMSSvc(55,2) = "wkssvc.dll"
  arMSSvc(56,0) = "AxInstSV" : arMSSvc(56,1) = "svchost.exe" : arMSSvc(56,2) = "AxInstSV.dll"
  arMSSvc(57,0) = "SensrSvc" : arMSSvc(57,1) = "svchost.exe" : arMSSvc(57,2) = "sensrsvc.dll"
  arMSSvc(58,0) = "AeLookupSvc" : arMSSvc(58,1) = "svchost.exe" : arMSSvc(58,2) = "aelupsvc.dll"
  arMSSvc(59,0) = "AppIDSvc" : arMSSvc(59,1) = "svchost.exe" : arMSSvc(59,2) = "appidsvc.dll"
  arMSSvc(60,0) = "ALG" : arMSSvc(60,1) = "alg.exe" : arMSSvc(60,2) = ""
  arMSSvc(61,0) = "AppMgmt" : arMSSvc(61,1) = "svchost.exe" : arMSSvc(61,2) = "appmgmts.dll"
  arMSSvc(62,0) = "BITS" : arMSSvc(62,1) = "svchost.exe" : arMSSvc(62,2) = "qmgr.dll"
  arMSSvc(63,0) = "BDESVC" : arMSSvc(63,1) = "svchost.exe" : arMSSvc(63,2) = "bdesvc.dll"
  arMSSvc(64,0) = "wbengine" : arMSSvc(64,1) = "wbengine.exe" : arMSSvc(64,2) = ""
  arMSSvc(65,0) = "bthserv" : arMSSvc(65,1) = "svchost.exe" : arMSSvc(65,2) = "bthserv.dll"
  arMSSvc(66,0) = "PeerDistSvc" : arMSSvc(66,1) = "svchost.exe" : arMSSvc(66,2) = "peerdistsvc.dll"
  arMSSvc(67,0) = "CertPropSvc" : arMSSvc(67,1) = "svchost.exe" : arMSSvc(67,2) = "certprop.dll"
  arMSSvc(68,0) = "COMSysApp" : arMSSvc(68,1) = "dllhost.exe" : arMSSvc(68,2) = ""
  arMSSvc(69,0) = "VaultSvc" : arMSSvc(69,1) = "lsass.exe" : arMSSvc(69,2) = ""
  arMSSvc(70,0) = "WdiSystemHost" : arMSSvc(70,1) = "svchost.exe" : arMSSvc(70,2) = "wdi.dll"
  arMSSvc(71,0) = "defragsvc" : arMSSvc(71,1) = "svchost.exe" : arMSSvc(71,2) = "defragsvc.dll"
  arMSSvc(72,0) = "MSDTC" : arMSSvc(72,1) = "msdtc.exe" : arMSSvc(72,2) = ""
  arMSSvc(73,0) = "EFS" : arMSSvc(73,1) = "lsass.exe" : arMSSvc(73,2) = ""
  arMSSvc(74,0) = "EapHost" : arMSSvc(74,1) = "svchost.exe" : arMSSvc(74,2) = "eapsvc.dll"
  arMSSvc(75,0) = "Fax" : arMSSvc(75,1) = "fxssvc.exe" : arMSSvc(75,2) = ""
  arMSSvc(76,0) = "getPlusHelper" : arMSSvc(76,1) = "svchost.exe" : arMSSvc(76,2) = "getPlus_Helper.dll"
  arMSSvc(77,0) = "hkmsvc" : arMSSvc(77,1) = "svchost.exe" : arMSSvc(77,2) = "kmsvc.dll"
  arMSSvc(78,0) = "hidserv" : arMSSvc(78,1) = "svchost.exe" : arMSSvc(78,2) = "hidserv.dll"
  arMSSvc(79,0) = "IKEEXT" : arMSSvc(79,1) = "svchost.exe" : arMSSvc(79,2) = "ikeext.dll"
  arMSSvc(80,0) = "UI0Detect" : arMSSvc(80,1) = "UI0Detect.exe" : arMSSvc(80,2) = ""
  arMSSvc(81,0) = "PolicyAgent" : arMSSvc(81,1) = "svchost.exe" : arMSSvc(81,2) = "ipsecsvc.dll"
  arMSSvc(82,0) = "KtmRm" : arMSSvc(82,1) = "svchost.exe" : arMSSvc(82,2) = "msdtckrm.dll"
  arMSSvc(83,0) = "lltdsvc" : arMSSvc(83,1) = "svchost.exe" : arMSSvc(83,2) = "lltdsvc.dll"
  arMSSvc(84,0) = "clr_optimization_v2.0.50727_32" : arMSSvc(84,1) = "mscorsvw.exe" : arMSSvc(84,2) = ""
  arMSSvc(85,0) = "MSiSCSI" : arMSSvc(85,1) = "svchost.exe" : arMSSvc(85,2) = "iscsiexe.dll"
  arMSSvc(86,0) = "swprv" : arMSSvc(86,1) = "svchost.exe" : arMSSvc(86,2) = "swprv.dll"
  arMSSvc(87,0) = "Netlogon" : arMSSvc(87,1) = "lsass.exe" : arMSSvc(87,2) = ""
  arMSSvc(88,0) = "napagent" : arMSSvc(88,1) = "svchost.exe" : arMSSvc(88,2) = "qagentRT.dll"
  arMSSvc(89,0) = "WPCSvc" : arMSSvc(89,1) = "svchost.exe" : arMSSvc(89,2) = "wpcsvc.dll"
  arMSSvc(90,0) = "pla" : arMSSvc(90,1) = "svchost.exe" : arMSSvc(90,2) = "pla.dll"
  arMSSvc(91,0) = "IPBusEnum" : arMSSvc(91,1) = "svchost.exe" : arMSSvc(91,2) = "ipbusenum.dll"
  arMSSvc(92,0) = "PNRPAutoReg" : arMSSvc(92,1) = "svchost.exe" : arMSSvc(92,2) = "pnrpauto.dll"
  arMSSvc(93,0) = "WPDBusEnum" : arMSSvc(93,1) = "svchost.exe" : arMSSvc(93,2) = "wpdbusenum.dll"
  arMSSvc(94,0) = "wercplsupport" : arMSSvc(94,1) = "svchost.exe" : arMSSvc(94,2) = "wercplsupport.dll"
  arMSSvc(95,0) = "ProtectedStorage" : arMSSvc(95,1) = "lsass.exe" : arMSSvc(95,2) = ""
  arMSSvc(96,0) = "QWAVE" : arMSSvc(96,1) = "svchost.exe" : arMSSvc(96,2) = "qwave.dll"
  arMSSvc(97,0) = "RasAuto" : arMSSvc(97,1) = "svchost.exe" : arMSSvc(97,2) = "rasauto.dll"
  arMSSvc(98,0) = "RasMan" : arMSSvc(98,1) = "svchost.exe" : arMSSvc(98,2) = "rasmans.dll"
  arMSSvc(99,0) = "SessionEnv" : arMSSvc(99,1) = "svchost.exe" : arMSSvc(99,2) = "sessenv.dll"
  arMSSvc(100,0) = "TermService" : arMSSvc(100,1) = "svchost.exe" : arMSSvc(100,2) = "termsrv.dll"
  arMSSvc(101,0) = "UmRdpService" : arMSSvc(101,1) = "svchost.exe" : arMSSvc(101,2) = "umrdp.dll"
  arMSSvc(102,0) = "RpcLocator" : arMSSvc(102,1) = "locator.exe" : arMSSvc(102,2) = ""
  arMSSvc(103,0) = "RemoteRegistry" : arMSSvc(103,1) = "svchost.exe" : arMSSvc(103,2) = "regsvc.dll"
  arMSSvc(104,0) = "seclogon" : arMSSvc(104,1) = "svchost.exe" : arMSSvc(104,2) = "seclogon.dll"
  arMSSvc(105,0) = "SstpSvc" : arMSSvc(105,1) = "svchost.exe" : arMSSvc(105,2) = "sstpsvc.dll"
  arMSSvc(106,0) = "SCardSvr" : arMSSvc(106,1) = "svchost.exe" : arMSSvc(106,2) = "SCardSvr.dll"
  arMSSvc(107,0) = "SCPolicySvc" : arMSSvc(107,1) = "svchost.exe" : arMSSvc(107,2) = "certprop.dll"
  arMSSvc(108,0) = "SNMPTRAP" : arMSSvc(108,1) = "snmptrap.exe" : arMSSvc(108,2) = ""
  arMSSvc(109,0) = "sppsvc" : arMSSvc(109,1) = "sppsvc.exe" : arMSSvc(109,2) = ""
  arMSSvc(110,0) = "sppuinotify" : arMSSvc(110,1) = "svchost.exe" : arMSSvc(110,2) = "sppuinotify.dll"
  arMSSvc(111,0) = "TabletInputService" : arMSSvc(111,1) = "svchost.exe" : arMSSvc(111,2) = "TabSvc.dll"
  arMSSvc(112,0) = "TapiSrv" : arMSSvc(112,1) = "svchost.exe" : arMSSvc(112,2) = "tapisrv.dll"
  arMSSvc(113,0) = "THREADORDER" : arMSSvc(113,1) = "svchost.exe" : arMSSvc(113,2) = "mmcss.dll"
  arMSSvc(114,0) = "TBS" : arMSSvc(114,1) = "svchost.exe" : arMSSvc(114,2) = "tbssvc.dll"
  arMSSvc(115,0) = "vds" : arMSSvc(115,1) = "vds.exe" : arMSSvc(115,2) = ""
  arMSSvc(116,0) = "VSS" : arMSSvc(116,1) = "vssvc.exe" : arMSSvc(116,2) = ""
  arMSSvc(117,0) = "WebClient" : arMSSvc(117,1) = "svchost.exe" : arMSSvc(117,2) = "webclnt.dll"
  arMSSvc(118,0) = "SDRSVC" : arMSSvc(118,1) = "svchost.exe" : arMSSvc(118,2) = "SDRSVC.dll"
  arMSSvc(119,0) = "WbioSrvc" : arMSSvc(119,1) = "svchost.exe" : arMSSvc(119,2) = "wbiosrvc.dll"
  arMSSvc(120,0) = "idsvc" : arMSSvc(120,1) = "infocard.exe" : arMSSvc(120,2) = ""
  arMSSvc(121,0) = "WcsPlugInService" : arMSSvc(121,1) = "svchost.exe" : arMSSvc(121,2) = "WcsPlugInService.dll"
  arMSSvc(122,0) = "wcncsvc" : arMSSvc(122,1) = "svchost.exe" : arMSSvc(122,2) = "wcncsvc.dll"
  arMSSvc(123,0) = "wudfsvc" : arMSSvc(123,1) = "svchost.exe" : arMSSvc(123,2) = "WUDFSvc.dll"
  arMSSvc(124,0) = "WerSvc" : arMSSvc(124,1) = "svchost.exe" : arMSSvc(124,2) = "WerSvc.dll"
  arMSSvc(125,0) = "Wecsvc" : arMSSvc(125,1) = "svchost.exe" : arMSSvc(125,2) = "wecsvc.dll"
  arMSSvc(126,0) = "FontCache" : arMSSvc(126,1) = "svchost.exe" : arMSSvc(126,2) = "FntCache.dll"
  arMSSvc(127,0) = "StiSvc" : arMSSvc(127,1) = "svchost.exe" : arMSSvc(127,2) = "wiaservc.dll"
  arMSSvc(128,0) = "msiserver" : arMSSvc(128,1) = "msiexec.exe" : arMSSvc(128,2) = ""
  arMSSvc(129,0) = "ehRecvr" : arMSSvc(129,1) = "ehRecvr.exe" : arMSSvc(129,2) = ""
  arMSSvc(130,0) = "ehSched" : arMSSvc(130,1) = "ehsched.exe" : arMSSvc(130,2) = ""
  arMSSvc(131,0) = "TrustedInstaller" : arMSSvc(131,1) = "TrustedInstaller.exe" : arMSSvc(131,2) = ""
  arMSSvc(132,0) = "FontCache3.0.0.0" : arMSSvc(132,1) = "PresentationFontCache.exe" : arMSSvc(132,2) = ""
  arMSSvc(133,0) = "WinRM" : arMSSvc(133,1) = "svchost.exe" : arMSSvc(133,2) = "WsmSvc.dll"
  arMSSvc(134,0) = "W32Time" : arMSSvc(134,1) = "svchost.exe" : arMSSvc(134,2) = "w32time.dll"
  arMSSvc(135,0) = "WinHttpAutoProxySvc" : arMSSvc(135,1) = "svchost.exe" : arMSSvc(135,2) = "winhttp.dll"
  arMSSvc(136,0) = "dot3svc" : arMSSvc(136,1) = "svchost.exe" : arMSSvc(136,2) = "dot3svc.dll"
  arMSSvc(137,0) = "Wlansvc" : arMSSvc(137,1) = "svchost.exe" : arMSSvc(137,2) = "wlansvc.dll"
  arMSSvc(138,0) = "wmiApSrv" : arMSSvc(138,1) = "WmiApSrv.exe" : arMSSvc(138,2) = ""
  arMSSvc(139,0) = "WwanSvc" : arMSSvc(139,1) = "svchost.exe" : arMSSvc(139,2) = "wwansvc.dll"
  arMSSvc(140,0) = "NcdAutoSetup" : arMSSvc(140,1) = "svchost.exe" : arMSSvc(140,2) = "NcdAutoSetup.dll"
  arMSSvc(141,0) = "LSM" : arMSSvc(141,1) = "svchost.exe" : arMSSvc(141,2) = "lsm.dll"
  arMSSvc(142,0) = "Wcmsvc" : arMSSvc(142,1) = "svchost.exe" : arMSSvc(142,2) = "wcmsvc.dll"
  arMSSvc(143,0) = "SystemEventsBroker" : arMSSvc(143,1) = "svchost.exe" : arMSSvc(143,2) = "SystemEventsBrokerServer.dll"
  arMSSvc(144,0) = "TimeBroker" : arMSSvc(144,1) = "svchost.exe" : arMSSvc(144,2) = "TimeBrokerServer.dll"
  arMSSvc(145,0) = "DeviceAssociationService" : arMSSvc(145,1) = "svchost.exe" : arMSSvc(145,2) = "das.dll"
  arMSSvc(146,0) = "BrokerInfrastructure" : arMSSvc(146,1) = "svchost.exe" : arMSSvc(146,2) = "bisrv.dll"
  arMSSvc(147,0) = "CertSvc" : arMSSvc(147,1) = "certsrv.exe" : arMSSvc(147,2) = ""
  arMSSvc(148,0) = "NTDS" : arMSSvc(148,1) = "lsass.exe" : arMSSvc(148,2) = ""
  arMSSvc(149,0) = "Dfs" : arMSSvc(149,1) = "dfssvc.exe" : arMSSvc(149,2) = ""
  arMSSvc(150,0) = "DFSR" : arMSSvc(150,1) = "DFSRs.exe" : arMSSvc(150,2) = ""
  arMSSvc(151,0) = "DHCPServer" : arMSSvc(151,1) = "svchost.exe" : arMSSvc(151,2) = "dhcpssvc.dll"
  arMSSvc(152,0) = "DNS" : arMSSvc(152,1) = "dns.exe" : arMSSvc(152,2) = ""
  arMSSvc(153,0) = "NtFrs" : arMSSvc(153,1) = "ntfrs.exe" : arMSSvc(153,2) = ""
  arMSSvc(154,0) = "IsmServ" : arMSSvc(154,1) = "ismserv.exe" : arMSSvc(154,2) = ""
  arMSSvc(155,0) = "kdc" : arMSSvc(155,1) = "lsass.exe" : arMSSvc(155,2) = ""
  arMSSvc(156,0) = "StorSvc" : arMSSvc(156,1) = "svchost.exe" : arMSSvc(156,2) = "storsvc.dll"
  arMSSvc(157,0) = "WatAdminSvc" : arMSSvc(157,1) = "WatAdminSvc.exe" : arMSSvc(157,2) = ""
  arMSSvc(158,0) = "PerfHost" : arMSSvc(158,1) = "PerfHost.exe" : arMSSvc(158,2) = ""
  arMSSvc(159,0) = "wlidsvc" : arMSSvc(159,1) = "svchost.exe" : arMSSvc(159,2) = "wlidsvc.dll"
  arMSSvc(160,0) = "WSService" : arMSSvc(160,1) = "svchost.exe" : arMSSvc(160,2) = "WSService.dll"
  arMSSvc(161,0) = "DsmSvc" : arMSSvc(161,1) = "svchost.exe" : arMSSvc(161,2) = "DeviceSetupManager.dll"
  arMSSvc(162,0) = "AllUserInstallAgent" : arMSSvc(162,1) = "svchost.exe" : arMSSvc(162,2) = "AUInstallAgent.dll"
  arMSSvc(163,0) = "NcaSvc" : arMSSvc(163,1) = "svchost.exe" : arMSSvc(163,2) = "ncasvc.dll"
  arMSSvc(164,0) = "PrintNotify" : arMSSvc(164,1) = "svchost.exe" : arMSSvc(164,2) = "PrintConfig.dll"
  arMSSvc(165,0) = "vmicvss" : arMSSvc(165,1) = "svchost.exe" : arMSSvc(165,2) = "ICSvc.dll"
  arMSSvc(166,0) = "vmicshutdown" : arMSSvc(166,1) = "svchost.exe" : arMSSvc(166,2) = "ICSvc.dll"
  arMSSvc(167,0) = "vmicrdv" : arMSSvc(167,1) = "svchost.exe" : arMSSvc(167,2) = "ICSvc.dll"
  arMSSvc(168,0) = "vmicheartbeat" : arMSSvc(168,1) = "svchost.exe" : arMSSvc(168,2) = "ICSvc.dll"
  arMSSvc(169,0) = "vmictimesync" : arMSSvc(169,1) = "svchost.exe" : arMSSvc(169,2) = "ICSvc.dll"
  arMSSvc(170,0) = "vmickvpexchange" : arMSSvc(170,1) = "svchost.exe" : arMSSvc(170,2) = "ICSvc.dll"
  arMSSvc(171,0) = "fhsvc" : arMSSvc(171,1) = "svchost.exe" : arMSSvc(171,2) = "fhsvc.dll"
  arMSSvc(172,0) = "DeviceInstall" : arMSSvc(172,1) = "svchost.exe" : arMSSvc(172,2) = "umpnpmgr.dll"
  arMSSvc(173,0) = "svsvc" : arMSSvc(173,1) = "svchost.exe" : arMSSvc(173,2) = "svsvc.dll"
  arMSSvc(174,0) = "WiaRpc" : arMSSvc(174,1) = "svchost.exe" : arMSSvc(174,2) = "wiarpc.dll"
  arMSSvc(175,0) = "AppHostSvc" : arMSSvc(175,1) = "svchost.exe" : arMSSvc(175,2) = "apphostsvc.dll"
  arMSSvc(176,0) = "DiagTrack" : arMSSvc(176,1) = "svchost.exe" : arMSSvc(176,2) = "diagtrack.dll"
  arMSSvc(177,0) = "WAS" : arMSSvc(177,1) = "svchost.exe" : arMSSvc(177,2) = "iisw3adm.dll"
  arMSSvc(178,0) = "W3SVC" : arMSSvc(178,1) = "svchost.exe" : arMSSvc(178,2) = "iisw3adm.dll"
  arMSSvc(179,0) = "IISADMIN" : arMSSvc(179,1) = "inetinfo.exe" : arMSSvc(179,2) = ""
  arMSSvc(180,0) = "SharedAccess" : arMSSvc(180,1) = "svchost.exe" : arMSSvc(180,2) = "ipnathlp.dll"
  arMSSvc(181,0) = "MSMQ" : arMSSvc(181,1) = "mqsvc.exe" : arMSSvc(181,2) = ""
  arMSSvc(182,0) = "MSMQTriggers" : arMSSvc(182,1) = "mqtgsvc.exe" : arMSSvc(182,2) = ""
  arMSSvc(183,0) = "iprip" : arMSSvc(183,1) = "svchost.exe" : arMSSvc(183,2) = "iprip.dll"
  arMSSvc(184,0) = "SNMP" : arMSSvc(184,1) = "snmp.exe" : arMSSvc(184,2) = ""

  If strOS = "WVA" Then
   arMSSvc(185,0) = "EMDMgmt" : arMSSvc(185,1) = "svchost.exe" : arMSSvc(185,2) = "emdmgmt.dll"  'ReadyBoost service
   arMSSvc(186,0) = "slsvc" : arMSSvc(186,1) = "SLsvc.exe" : arMSSvc(186,2) = ""  'Software Licensing service
   arMSSvc(187,0) = "SLUINotify" : arMSSvc(187,1) = "svchost.exe" : arMSSvc(187,2) = "SLUINotify.dll"  'License Activation Scheduler
   arMSSvc(188,0) = "DFSR" : arMSSvc(188,1) = "DFSR.exe" : arMSSvc(188,2) = ""  'Distributed File System Replication
   arMSSvc(189,0) = "LPDSVC" : arMSSvc(189,1) = "tcpsvcs.exe" : arMSSvc(189,2) = ""  'TCP/IP Print Server
   arMSSvc(190,0) = "NfsClnt" : arMSSvc(190,1) = "nfsclnt.exe" : arMSSvc(190,2) = ""  'Linux NFS client
   arMSSvc(191,0) = "WcesComm" : arMSSvc(191,1) = "svchost.exe" : arMSSvc(191,2) = "wcescomm.dll"  'ActiveSync Connection Manager
   arMSSvc(192,0) = "ehstart" : arMSSvc(192,1) = "svchost.exe" : arMSSvc(192,2) = "ehstart.dll"  'Windows Media Center Service Launcher
   arMSSvc(193,0) = "PNRPAutoReg" : arMSSvc(193,1) = "svchost.exe" : arMSSvc(193,2) = "p2psvc.dll"  'Peer Name Resolution Protocol Machine Name Publication Service
  End If

  If strOSSS = "WN8" Or strOSSS = "W10" Then
   arMSSvc(185,0) = "workfolderssvc" : arMSSvc(185,1) = "svchost.exe" : arMSSvc(185,2) = "workfolderssvc.dll"
   arMSSvc(186,0) = "NcbService" : arMSSvc(186,1) = "svchost.exe" : arMSSvc(186,2) = "ncbservice.dll"
   arMSSvc(187,0) = "AppXSvc" : arMSSvc(187,1) = "svchost.exe" : arMSSvc(187,2) = "appxdeploymentserver.dll"
  End If

  If strOSSS = "W10" Then
   arMSSvc(188,0) = "AppReadiness" : arMSSvc(188,1) = "svchost.exe" : arMSSvc(188,2) = "AppReadiness.dll"
   arMSSvc(189,0) = "ClipSVC" : arMSSvc(189,1) = "svchost.exe" : arMSSvc(189,2) = "ClipSVC.dll"
   arMSSvc(190,0) = "CoreMessagingRegistrar" : arMSSvc(190,1) = "svchost.exe" : arMSSvc(190,2) = "coremessaging.dll"
   arMSSvc(191,0) = "DoSvc" : arMSSvc(191,1) = "svchost.exe" : arMSSvc(191,2) = "dosvc.dll"
   arMSSvc(192,0) = "DsSvc" : arMSSvc(192,1) = "svchost.exe" : arMSSvc(192,2) = "dssvc.dll"
   arMSSvc(193,0) = "lfsvc" : arMSSvc(193,1) = "svchost.exe" : arMSSvc(193,2) = "lfsvc.dll"
   arMSSvc(194,0) = "MSMQ" : arMSSvc(194,1) = "mqsvc.exe" : arMSSvc(194,2) = ""
   arMSSvc(195,0) = "smphost" : arMSSvc(195,1) = "svchost.exe" : arMSSvc(195,2) = "smphost.dll"
   arMSSvc(196,0) = "StateRepository" : arMSSvc(196,1) = "svchost.exe" : arMSSvc(196,2) = "windows.staterepository.dll"
   arMSSvc(197,0) = "tiledatamodelsvc" : arMSSvc(197,1) = "svchost.exe" : arMSSvc(197,2) = "tileobjserver.dll"
   arMSSvc(198,0) = "UserManager" : arMSSvc(198,1) = "svchost.exe" : arMSSvc(198,2) = "usermgr.dll"
   arMSSvc(199,0) = "LicenseManager" : arMSSvc(199,1) = "svchost.exe" : arMSSvc(199,2) = "LicenseManagerSvc.dll"
   arMSSvc(200,0) = "usosvc" : arMSSvc(200,1) = "svchost.exe" : arMSSvc(200,2) = "usocore.dll"
   arMSSvc(201,0) = "TimeBrokerSvc" : arMSSvc(201,1) = "svchost.exe" : arMSSvc(201,2) = "TimeBrokerServer.dll"
   arMSSvc(202,0) = "SensorService" : arMSSvc(202,1) = "svchost.exe" : arMSSvc(202,2) = "SensorService.dll"
   arMSSvc(203,0) = "RmSvc" : arMSSvc(203,1) = "svchost.exe" : arMSSvc(203,2) = "RMapi.dll"
   arMSSvc(204,0) = "CDPSvc" : arMSSvc(204,1) = "svchost.exe" : arMSSvc(204,2) = "CDPSvc.dll"
   arMSSvc(205,0) = "WpnService" : arMSSvc(205,1) = "svchost.exe" : arMSSvc(205,2) = "WpnService.dll"
   arMSSvc(206,0) = "wisvc" : arMSSvc(206,1) = "svchost.exe" : arMSSvc(206,2) = "flightsettings.dll"
   arMSSvc(207,0) = "dmwappushservice" : arMSSvc(207,1) = "svchost.exe" : arMSSvc(207,2) = "dmwappushsvc.dll"
   arMSSvc(208,0) = "SmsRouter" : arMSSvc(208,1) = "svchost.exe" : arMSSvc(208,2) = "SmsRouterSvc.dll"
   arMSSvc(209,0) = "WdNisSvc" : arMSSvc(209,1) = "NisSrv.exe" : arMSSvc(209,2) = ""
   arMSSvc(210,0) = "DusmSvc" : arMSSvc(210,1) = "svchost.exe" : arMSSvc(210,2) = "dusmsvc.dll"
   arMSSvc(211,0) = "SecurityHealthService" : arMSSvc(211,1) = "SecurityHealthService.exe" : arMSSvc(211,2) = ""
   arMSSvc(212,0) = "TokenBroker" : arMSSvc(212,1) = "svchost.exe" : arMSSvc(212,2) = "TokenBroker.dll"
   arMSSvc(213,0) = "NgcCtnrSvc" : arMSSvc(213,1) = "svchost.exe" : arMSSvc(213,2) = "NgcCtnrSvc.dll"
   arMSSvc(214,0) = "NgcSvc" : arMSSvc(214,1) = "svchost.exe" : arMSSvc(214,2) = "ngcsvc.dll"
   arMSSvc(215,0) = "SEMgrSvc" : arMSSvc(215,1) = "svchost.exe" : arMSSvc(215,2) = "SEMgrSvc.dll"
   arMSSvc(216,0) = "InstallService" : arMSSvc(215,1) = "svchost.exe" : arMSSvc(216,2) = "InstallService.dll"
   arMSSvc(217,0) = "camsvc" : arMSSvc(215,1) = "svchost.exe" : arMSSvc(217,2) = "CapabilityAccessManager.dll"
  End If

'   arMSSvc(218,0) = "" : arMSSvc(218,1) = "svchost.exe" : arMSSvc(218,2) = ".dll"

End If  'filling MS default services array

 'Services collection, Service object,
 Dim colSvce, oSvce
 'lowest-sort name holder, temp variables x 3
 Dim intLSS, str1stName, strT0, strT1, strT2
 Dim flagSM : flagSM = False  'Safe Mode flag

 'for W2K/WXP/WVa/Wn7, determine if running in Safe Mode
 If strOS <> "NT4" Then

  strKey = "SYSTEM\CurrentControlSet\Control"
  On Error Resume Next
   intErrNum = oReg.GetStringValue (HKLM,strKey,"SystemStartOptions",strValue)
  On Error GoTo 0

  'if name exists
  If intErrNum = 0 Then
   'check if in Safe Mode
   If InStr(LCase(strValue),"safeboot") <> 0 Then flagSM = True
  End If

 End If  'W2K/WXP/WVa/Wn7?

 'set up title line for normal, ShowAll, Safe Mode operation
 strTitle = "Running Services (Display Name, Service Name, Path {Service DLL}):"
 If flagShowAll Then strTitle = "All Running Services (Display Name, Service Name, Path {Service DLL}):"
 If flagSM Then strTitle = "All Non-Disabled Services (Display Name, " &_
  "Service Name, Path {Service DLL}):"

 'if in Safe Mode
 If flagSM Then

  'get collection of services with Auto or Manual "Startup type"
  Set colSvce = GetObject("winmgmts:\root\cimv2").ExecQuery("SELECT DisplayName, " &_
   "Name, PathName FROM Win32_Service WHERE StartMode = ""Manual"" " &_
   "Or StartMode = ""Auto""")

 'not in Safe Mode
 Else

  'get collection of started services
  Set colSvce = GetObject("winmgmts:\root\cimv2").ExecQuery("SELECT DisplayName, " &_
   "Name, PathName FROM Win32_Service WHERE Started = True")

 End If  'safe mode?

 'sort services by display name

 'get the count
 On Error Resume Next
  intCnt = colSvce.Count
  intErrNum = Err.Number : Err.Clear
 On Error GoTo 0

 'output warning and exit if count impeded
 If intErrNum <> 0 Then
  flagIWarn = True
  TitleLineWrite
  oFN.WriteLine vbCRLF & IWarn &_
   "The running services cannot be counted." & vbCRLF &_
   "Presence of a spyware service is suspected." & vbCRLF &_
   "The script has been forced to exit."
  SRClose
  WScript.Quit
 End If

 'set up two arrays: work array & sorted array
 Dim arSvces() : ReDim arSvces(intCnt-1, 2)  'services array

 i = 0

 'transfer data from collection to array
 For Each oSvce in colSvce

  arSvces(i,0) = oSvce.DisplayName : arSvces(i,1) = oSvce.Name

  'check for null values or empty strings returned by WMI
  If IsNull(oSvce.PathName) Then
   arSvces(i,2) = "(null value)"
  ElseIf oSvce.PathName = "" Then
   arSvces(i,2) = "(empty string)"
  Else
   arSvces(i,2) = oSvce.PathName
  End If

  i = i + 1

 Next  'service in collection

 Set colSvce=Nothing

 'for every service in array up to the next to last one
 For i = 0 To UBound(arSvces,1) - 1

  'store array row in temp variables
  strT0 = arSvces(i,0)
  strT1 = arSvces(i,1)
  strT2 = arSvces(i,2)

  'initialize the sorted name & lowest-sort subscript
  str1stName = arSvces(i,0)
  intLSS = i

  'for every subsequent service in array up to the last one
  For j = i + 1 To UBound(arSvces,1)

   'if current array name < saved lowest-sort name,
   'reset sorted array data and
   'set lowest-sort subscript = current array subscript
   If LCase(arSvces(j,0)) < LCase(str1stName) Then
    str1stName = arSvces(j,0)
    intLSS = j
   End If

  Next  'j array element

  'set current array position = lowest-sort subscript element
  arSvces(i,0) = arSvces(intLSS,0)
  arSvces(i,1) = arSvces(intLSS,1)
  arSvces(i,2) = arSvces(intLSS,2)
  'save data formerly in current array position to array position just vacated
  arSvces(intLSS,0) = strT0
  arSvces(intLSS,1) = strT1
  arSvces(intLSS,2) = strT2

 Next  'i sorted name array element

 'for every service sorted by display name
 For i = 0 To UBound(arSvces,1)

  'format path name for output
  If arSvces(i,2) = "(null value)" Then
   strPathNameOut = "(null value)"
  ElseIf arSvces(i,2) = "(empty string)" Then
   strPathNameOut = "(empty string)"
  Else
   strPathNameOut = arSvces(i,2)
  End If

  intMSSvcNo = -1  'assume not an MS Service

  'find company name
  strCN = CoName(IDExe(arSvces(i,2)))

  'if service name found in MS default services array, save array subscript
  For j = 0 To UBound(arMSSvc,1)

   If LCase(arSvces(i,1)) = LCase(arMSSvc(j,0)) Then
     intMSSvcNo = j : Exit For
   End If

  Next  'arMSSvc (MS Service)

  'for services with unique file names
  If InStr(LCase(arSvces(i,2)),"services.exe") = 0 And _
     InStr(LCase(arSvces(i,2)),"svchost") = 0 Then

   'find last backslash in service executable path
   'fixed bug here: InStrRev should operate on IDExe output,
   'since IDExe is also used in strExeName assignment statement
   '(IDExe is useful to delete embedding quotes)
   intLBSP = InStrRev(IDExe(arSvces(i,2)),BS)

   'set position to 0 if no backslash present
   If IsNull(intLBSP) Then intLBSP = 0
   'extract service executable
   strExeName = Mid(IDExe(arSvces(i,2)),intLBSP+1)

   'if not MS default service Or ShowAll
   If intMSSvcNo < 0 Or flagShowAll Then

    If strTitle <> "" Then
     TitleLineWrite : oFN.WriteBlankLines (1)
    End If

    'output display name, service name, path
    oFN.WriteLine arSvces(i,0) & ", " &_
     arSvces(i,1) & ", " & strPathNameOut & strCN

   'if MS default service And (executable name or CoName doesn't match expected value)
   ElseIf intMSSvcNo >= 0 And _
    (LCase(strExeName) <> LCase(arMSSvc(intMSSvcNo,1)) Or _
    strCN <> MS) Then

    If strTitle <> "" Then
     TitleLineWrite : oFN.WriteBlankLines (1)
    End If

    'output display name, service name, path
    oFN.WriteLine arSvces(i,0) & ", " &_
     arSvces(i,1) & ", " & strPathNameOut & strCN

   End If  'MS default service with unexpected executable/CoName?

  'shared process -- look for ServiceDLL value in Parameter subkey
  ElseIf InStr(LCase(arSvces(i,2)),"svchost") > 0 And _
   InStr(LCase(arSvces(i,2))," -k") > 0 Then

   strKey = "System\CurrentControlSet\Services\"
   On Error Resume Next
    intErrNum = oReg.GetExpandedStringValue (HKLM,strKey & arSvces(i,1) &_
     "\Parameters","ServiceDll",strValue)
   On Error GoTo 0

   'prepare output for missing Parameters key or ServiceDLL value
   strLine = " {(missing data)}"
   strCN = CoName(IDExe(strValue))

   If intErrNum = 0 And strValue <> "" Then

    strLine = " {" & strValue & strCN & "}"

    'extract ServiceDLL filename.ext
    strDLL = Fso.GetFileName(strValue)

    flagMatch = True
    'if ShowAll Or DLL name/CoName have unexpected values
    If flagShowAll Or LCase(strCN) <> " [ms]" Or intMSSvcNo = -1 Then
     flagMatch = False
    ElseIf LCase(strDLL) <> LCase(arMSSvc(intMSSvcNo,2)) Then
     flagMatch = False
    End If

    If Not flagMatch Then

     If strTitle <> "" Then
      TitleLineWrite : oFN.WriteBlankLines (1)
     End If

     'output display name, service name, path
     oFN.WriteLine arSvces(i,0) & ", " &_
      arSvces(i,1) & ", " & strPathNameOut & strLine

    End If  'flagMatch?

   Else  'Parameters\ServiceDll not found so check service key

    On Error Resume Next
     intErrNum1 = oReg.GetExpandedStringValue (HKLM,strKey & arSvces(i,1), _
      "ServiceDll",strValue1)
    On Error GoTo 0

    'prepare output for missing Parameters key or ServiceDLL value
    strLine = " {(missing data)}"
    strCN = CoName(IDExe(strValue1))

    If intErrNum1 = 0 And strValue1 <> "" Then

     strLine = " {" & strValue1 & strCN & "}"

     'extract ServiceDLL filename.ext
     strDLL = Fso.GetFileName(strValue1)

     flagMatch = True
     'if ShowAll Or DLL name/CoName have unexpected values
     If flagShowAll Or LCase(strCN) <> " [ms]" Or intMSSvcNo = -1 Then
      flagMatch = False
     ElseIf LCase(strDLL) <> LCase(arMSSvc(intMSSvcNo,2)) Then
      flagMatch = False
     End If

     If Not flagMatch Then

      If strTitle <> "" Then
       TitleLineWrite : oFN.WriteBlankLines (1)
      End If

      'output display name, service name, path
      oFN.WriteLine arSvces(i,0) & ", " &_
       arSvces(i,1) & ", " & strPathNameOut & strLine

     End If  'flagMatch?

    End If  'ServiceDll exists at service key?

   End If  'Parameters\ServiceDll exists?

  'services.exe
  Else

   'extract service executable filename.ext
   strExeName = Fso.GetFileName(arSvces(i,2))

   flagMatch = True
   'if ShowAll Or service name <> Services.exe or CoName <> MS
   If flagShowAll Or LCase(strCN) <> " [ms]" Or intMSSvcNo = -1 Then
     flagMatch = False
   ElseIf LCase(strExeName) <> LCase(arMSSvc(intMSSvcNo,1)) Then
     flagMatch = False
   End If

   If Not flagMatch Then
    If strTitle <> "" Then
     TitleLineWrite : oFN.WriteBlankLines (1)
    End If

    'output display name, service name, path
    oFN.WriteLine arSvces(i,0) & ", " &_
     arSvces(i,1) & ", " & strPathNameOut & strCN
   End If

  End If  'independent file, svchost, or services?

 Next  'service file

 'recover array memory
 ReDim arSvces(0,0) : ReDim arMSSvc(0,0)

End If  'NT4-type OS?

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

End If  'SecTest?




'#33. Safe Mode Drivers & Services

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

If strOS <> "W98" And strOS <> "WME" And strOS <> "NT4" Then

 'prepare title line
 strTitle = "Safe Mode Drivers & Services (subkey name, subkey default value):"

 Dim arSBSK(1) : arSBSK(0) = "Minimal" : arSBSK(1) = "Network"  'SafeBoot Sub-Keys

 Dim arSBMin(158)

 arSBMin(0) = "{36FC9E60-C465-11CF-8056-444553540000}"
 arSBMin(1) = "{4D36E965-E325-11CE-BFC1-08002BE10318}"
 arSBMin(2) = "{4D36E967-E325-11CE-BFC1-08002BE10318}"
 arSBMin(3) = "{4D36E969-E325-11CE-BFC1-08002BE10318}"
 arSBMin(4) = "{4D36E96A-E325-11CE-BFC1-08002BE10318}"
 arSBMin(5) = "{4D36E96B-E325-11CE-BFC1-08002BE10318}"
 arSBMin(6) = "{4D36E96F-E325-11CE-BFC1-08002BE10318}"
 arSBMin(7) = "{4D36E977-E325-11CE-BFC1-08002BE10318}"
 arSBMin(8) = "{4D36E97B-E325-11CE-BFC1-08002BE10318}"
 arSBMin(9) = "{4D36E97D-E325-11CE-BFC1-08002BE10318}"
 arSBMin(10) = "{4D36E980-E325-11CE-BFC1-08002BE10318}"
 arSBMin(11) = "{533C5B84-EC70-11D2-9505-00C04F79DEAF}"
 arSBMin(12) = "{71A27CDD-812A-11D0-BEC7-08002BE2092F}"
 arSBMin(13) = "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}"
 arSBMin(14) = "AppMgmt" : arSBMin(15) = "Base" : arSBMin(16) = "Boot Bus Extender"
 arSBMin(17) = "Boot file system" : arSBMin(18) = "CryptSvc" : arSBMin(19) = "DcomLaunch"
 arSBMin(20) = "dmadmin" : arSBMin(21) = "dmboot.sys" : arSBMin(22) = "dmio.sys"
 arSBMin(23) = "dmload.sys" : arSBMin(24) = "dmserver" : arSBMin(25) = "EventLog"
 arSBMin(26) = "File system" : arSBMin(27) = "Filter" : arSBMin(28) = "HelpSvc"
 arSBMin(29) = "Netlogon" : arSBMin(30) = "PCI Configuration" : arSBMin(31) = "PlugPlay"
 arSBMin(32) = "PNP Filter" : arSBMin(33) = "Primary disk" : arSBMin(34) = "RpcSs"
 arSBMin(35) = "SCSI Class" : arSBMin(36) = "sermouse.sys" : arSBMin(37) = "sr.sys"
 arSBMin(38) = "SRService" : arSBMin(39) = "System Bus Extender" : arSBMin(40) = "vga.sys"
 arSBMin(41) = "vgasave.sys" : arSBMin(42) = "WinMgmt"

 'W2K
 arSBMin(43) = "sglfb.sys" : arSBMin(44) = "tga.sys"

 arSBMin(45) = "AFD" : arSBMin(46) = "Browser"
 arSBMin(47) = "Dhcp" : arSBMin(48) = "DnsCache"
 arSBMin(49) = "ip6fw.sys" : arSBMin(50) = "ipnat.sys"

 arSBMin(51) = "LanmanServer" : arSBMin(52) = "LanmanWorkstation"
 arSBMin(53) = "LmHosts" : arSBMin(54) = "Messenger"
 arSBMin(55) = "NDIS" : arSBMin(56) = "NDIS Wrapper"
 arSBMin(57) = "Ndisuio" : arSBMin(58) = "NetBIOS"
 arSBMin(59) = "NetBIOSGroup" : arSBMin(60) = "NetBT"

 arSBMin(61) = "NetDDEGroup" : arSBMin(62) = "NetMan"
 arSBMin(63) = "Network" : arSBMin(64) = "NetworkProvider"
 arSBMin(65) = "NtLmSsp" : arSBMin(66) = "PNP_TDI"
 arSBMin(67) = "rdpcdd.sys" : arSBMin(68) = "rdpdd.sys"
 arSBMin(69) = "rdpwd.sys" : arSBMin(70) = "rdsessmgr"

 arSBMin(71) = "SharedAccess" : arSBMin(72) = "Streams Drivers"
 arSBMin(73) = "Tcpip" : arSBMin(74) = "TDI"
 arSBMin(75) = "tdpipe.sys" : arSBMin(76) = "tdtcp.sys"
 arSBMin(77) = "termservice" : arSBMin(78) = "WZCSVC"
 arSBMin(79) = "{4D36E972-E325-11CE-BFC1-08002BE10318}" : arSBMin(80) = "{4D36E973-E325-11CE-BFC1-08002BE10318}"

 arSBMin(81) = "{4D36E974-E325-11CE-BFC1-08002BE10318}" : arSBMin(82) = "{4D36E975-E325-11CE-BFC1-08002BE10318}"

 'Misc
 arSBMin(83) = "vds"  'Virtual Disk Service
 arSBMin(84) = "Wdf01000.sys"  'WDF Dynamic (MS)

'WXP
 arSBMin(85) = "UploadMgr"

 'WVa
 arSBMin(86) = "AppInfo"  'Service Informations d'application (.DLL)
 arSBMin(87) = "KeyIso"  'Service d'isolation de clé CNG (.DLL)
 arSBMin(88) = "NTDS"  'NT Directory Service
 arSBMin(89) = "ProfSvc"  'User Profile Service
 arSBMin(90) = "sacsvr"  'Emergency Management Services Special Administration Console
 arSBMin(91) = "SWPRV"  'Software Shadow Copy Provider
 arSBMin(92) = "TabletInputService"  'Tablet PC Input Service
 arSBMin(93) = "TBS"  'Trusted Platform Module Base Services
 arSBMin(94) = "TrustedInstaller"  'Windows Modules Installer
 arSBMin(95) = "volmgr.sys"  'Volume Manager Driver
 arSBMin(96) = "volmgrx.sys"  'Dynamic Volume Manager
 arSBMin(97) = "WinDefend"  'Windows Defender
 arSBMin(98) = "{6BDD1FC1-810F-11D0-BEC7-08002BE2092F}"  'IEEE 1394 Bus host controllers
 arSBMin(99) = "{D48179BE-EC20-11D1-B6B8-00C04FA372A7}"  'SBP2 IEEE 1394 Devices
 arSBMin(100) = "{D94EE5D8-D189-4994-83D2-F68D7D41B0E6}"  'SecurityDevices

 arSBMin(101) = "BFE"
 arSBMin(102) = "bowser"
 arSBMin(103) = "dfsc"
 arSBMin(104) = "Dot3Svc"
 arSBMin(105) = "Eaphost"
 arSBMin(106) = "IKEEXT"
 arSBMin(107) = "MPSDrv"
 arSBMin(108) = "MPSSvc"
 arSBMin(109) = "mrxsmb"
 arSBMin(110) = "mrxsmb10"
 arSBMin(111) = "mrxsmb20"
 arSBMin(112) = "NativeWifiP"
 arSBMin(113) = "netprofm"
 arSBMin(114) = "NlaSvc"
 arSBMin(115) = "Nsi"
 arSBMin(116) = "nsiproxy.sys"
 arSBMin(117) = "PolicyAgent"
 arSBMin(118) = "rdbss"
 arSBMin(119) = "rdpencdd.sys"
 arSBMin(120) = "ScardSvr"
 arSBMin(121) = "Wlansvc"
 arSBMin(122) = "WudfUsbccidDriver"
 arSBMin(123) = "{50DD5230-BA8A-11D1-BF5D-0000F805F530}"

 'Wn7 RC1
 arSBMin(124) = "EFS"  'Encrypting File System
 arSBMin(125) = "Power"
 arSBMin(126) = "RpcEptMapper"  'RPC EndPoint Mapper
 arSBMin(127) = "vmms"  'Virtual Machine Management Service
 arSBMin(128) = "WudfPf"  'User Mode Driver Frameworks Platform
 arSBMin(129) = "WudfRd"  'User Mode Driver Frameworks Reflector
 arSBMin(130) = "WudfSvc"  'User Mode Driver Frameworks Host Process Manager
 arSBMin(131) = "ndiscap"
 arSBMin(132) = "VaultSvc"

 'WS2K3
 arSBMin(133) = "wd.sys"  'Watchdog Timer Driver

 'W2KS
 arSBMin(134) = "NBF"  '
 arSBMin(135) = "nbf.sys"  '
 arSBMin(136) = "nm"  '
 arSBMin(137) = "nm.sys"  '
 arSBMin(138) = "ProtectedStorage"  '

 'Wn8
 arSBMin(139) = "BasicDisplay.sys"
 arSBMin(140) = "BasicRender.sys"
 arSBMin(141) = "BrokerInfrastructure"
 arSBMin(142) = "DeviceInstall"
 arSBMin(143) = "dxgkrnl.sys"
 arSBMin(144) = "FsDepends.sys"
 arSBMin(145) = "LSM"
 arSBMin(146) = "SmartcardSimulator"
 arSBMin(147) = "VirtualSmartcardReader"
 arSBMin(148) = "Wcmsvc"
 arSBMin(149) = "{9DA2B80F-F89F-4A49-A5C2-511B085B9E8A}"  'Enhanced Storage Devices
 arSBMin(150) = "{A0A588A4-C46F-4B37-B7EA-C82FE89870C6}"  'SDA Standard Compliant SD Host Controller

'W10

 arSBMin(151) = "Ahcache.sys"
 arSBMin(152) = "CoreMessagingRegistrar"
 arSBMin(153) = "StateRepository"
 arSBMin(154) = "SystemEventsBroker"
 arSBMin(155) = "TileDataModelSvc"
 arSBMin(156) = "UserManager"
 arSBMin(157) = "SpbCx.sys"
 arSBMin(158) = "uefi.sys"

' arSBMin(159) = ""  '

 For i = 0 To UBound(arSBSK)  'for each SafeBoot sub-key

  strKey = "System\CurrentControlSet\Control\SafeBoot\" & arSBSK(i)

  'form sub-title
  strSubTitle = SOCA("HKLM" & BS & strKey & BS)

  'search for driver/service names
  intErrNum = oReg.EnumKey (HKLM,strKey,arNames)

  'if names exist
  If intErrNum = 0 And IsArray(arNames) Then

   'for each name
   For Each strSubKey In arNames

    'look for name's title
    On Error Resume Next
     oReg.GetStringValue HKLM,strKey & BS & strSubKey,"",strValue
    On Error GoTo 0

    'assume not allowed
    flagFound = False : strWarn = ""

    'for each allowed driver/service
    For j = 0 To UBound(arSBMin)

     'toggle flag if allowed name = driver/service name
     If LCase(strSubKey) = LCase(arSBMin(j)) Then
      flagFound = True : Exit For
     End If

    Next  'allowed driver/service

    'toggle IWarn if driver/service not allowed
    If Not flagFound Then
     strWarn = IWarn : flagIWarn = True
    End If

    'output if not allowed or ShowAll
    If Not flagFound Or flagShowAll Then

     'skip line right after sub-title
     If strSubTitle = "" Then
      TitleLineWrite
     Else
      TitleLineWrite : oFN.WriteBlankLines (1)
     End If

     'if title MT, output "(title not found)"
     If strValue = "" Then
      oFN.WriteLine strWarn & strSubKey & ", (title not found)"
     Else  'title not MT
      oFN.WriteLine strWarn & strSubKey & ", " & strValue
     End If  'title MT?

    End If  'not allowed or ShowAll?

   Next  'strSubKey

  Else  'names not found

   TitleLineWrite
   oFN.WriteLine vbCRLF & "Safe Mode " & arSBSK(i) & " drivers and services not found!"

  End If  'names found?

 Next  'SafeBoot sub-key

End If  '!W98 & !WME & !NT4?

End If  'SecTest?




'#34. Accessibility Tools

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'prepare title line
strTitle = "Accessibility Tools:"

'in W2K, recurse Utility Manager subkeys
If strOS = "W2K" Then

 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Utility Manager"
 strSubTitle = SOCA("HKLM" & BS & strKey & BS)

 ReDim arAllowedNames(2) : arAllowedNames(0) = "magnifier.exe"
 arAllowedNames(1) = "narrator.exe" : arAllowedNames(2) = "osk.exe"

 'find all the subkeys
 oReg.EnumKey HKLM, strKey, arSubKeys

 'enumerate data if present
 If IsArray(arSubKeys) Then

  'for each key
  For Each strSubKey In arSubKeys

   'get the configured startup values (dword returned as string)

   strValue1 = RtnValue (HKLM, strKey & BS & strSubKey, "Start with Utility Manager", REG_DWORD)
   strValue2 = RtnValue (HKLM, strKey & BS & strSubKey, "Start with Windows", REG_DWORD)

   'if startup enabled (dword = 1)
   If LCase(strValue1) = "dword:0x00000001" Or LCase(strValue2) = "dword:0x00000001" Then

    'use new subtitle
    strSubTitle = "HKLM" & BS & strKey & BS & strSubKey & BS

    strWarn = IWarn  'assume app path is not an allowed executable

    'retrieve Application Path value & find CN
    strValue3 = RtnValue (HKLM, strKey & BS & strSubKey, "Application Path", REG_SZ)
    strCN = CoName(IDExe(strValue3))

    'empty strWarn if app path/CoName OK or app path empty
    For i = 0 To UBound(arAllowedNames)
     If (LCase(strValue3) = arAllowedNames(i) And strCN = MS) Or _
      LCase(strValue3) = "(empty string)" Then
      strWarn = "" : Exit For
     End If
    Next

    'display warning in footer if app path executable not allowed
    If strWarn <> "" Then flagIWarn = True

    'output the title line if not already done
    TitleLineWrite

    'retrieve Display Name value
    strValue4 = RtnValue (HKLM, strKey & BS & strSubKey, "Display Name", REG_SZ)

    'output data
    oFN.WriteLine strWarn & "Application Path = " &_
     strValue3 & strCN & vbCRLF & "Display Name = " & strValue4
    If LCase(strValue1) = "dword:0x00000001" Then _
     oFN.WriteLine "Start with Utility Manager = " & strValue1
    If LCase(strValue2) = "dword:0x00000001" Then _
     oFN.WriteLine "Start with Windows = " & strValue2

   End If  'sub-key name exists & dword = 1

  Next  'sub-key

 End If  'sub-key array exists?

 'if ShowAll, output the key name if not already done
 If flagShowAll Then TitleLineWrite

 'clean up
 strTitle = "" : strSubTitle = "" : strWarn = ""
 ReDim arAllowedNames(0)

End If  'W2K?


'examine 4 WVa/Wn7 keys for accessibility tool names
If strOS = "WVA" Or strOS = "WN7" Then

 Public intUB : intUB = -1  'Upper Bound of unique accessibility tool array

 ReDim arAllowedNames(2) : arAllowedNames(0) = "magnify.exe"
 arAllowedNames(1) = "narrator.exe" : arAllowedNames(2) = "osk.exe"

 '2 principal keys: HKCU/HKLM...Accessibility
 strKey = "Software\Microsoft\Windows NT\CurrentVersion\Accessibility"

 'for each hive
 For ctrCH = 0 To 1

  strSubTitle = SOCA(arHives(ctrCH,0) & BS & strKey & BS)

  On Error Resume Next
   intErrNum = oReg.GetStringValue (arHives(ctrCH,1),strKey,"Configuration",strValue)
  On Error GoTo 0

  'if strValue exists & not empty or ShowAll
  If (intErrNum = 0 And strValue <> "") Or flagShowAll Then

   If intErrNum = 0 And strValue <> "" Then

    TitleLineWrite

    'output Configuration value
    oFN.WriteLine "Configuration = " & strValue

    'parse comma-delimited strValue into Public arAcc array
    StrParse2Unique strValue

   Else  'ShowAll

    TitleLineWrite
    oFN.WriteLine "Configuration = (value not set)"

   End If 'strValue exists?

  End If  'strValue exists or ShowAll?

  'output if ShowAll
  If flagShowAll Then TitleLineWrite

 Next  'hive


 'HKCU...AccessibilityTemp
 strKey = "Software\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp"

 strSubTitle = "HKCU\" & strKey & BS

 'find the names array
 oReg.EnumValues HKCU, strKey, arNames, arType

 'if names array found
 If IsArray(arNames) Then

  TitleLineWrite

  For Each strName In arNames

   'output the DWORD values as strings
   strValue = RtnValue (HKCU, strKey, strName, REG_DWORD)
   oFN.WriteLine strName & " = " & strValue

   'add unique names to array
   AppUnique2DynArr strName,1,Len(strName)

  Next

 End If


 'HKLM...Accessibility/Session#
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility"
 strSubTitle = "HKLM\" & strKey & "\Session#\"

 flagFound = False  'true if Session# key found

 'find the subkeys
 oReg.EnumKey HKLM, strKey, arSubKeys

 'enumerate data if present
 If IsArray(arSubKeys) Then

  For Each strSubKey in arSubKeys

   'save the subkey name if first seven letters are "session"
   If LCase(Left(Trim(strSubKey),7)) = "session" Then
    flagFound = True : strName = strSubKey : Exit For
   End If

  Next

  'if Session# key found
  If flagFound Then

   'look for Configuration value
   On Error Resume Next
    intErrNum = oReg.GetStringValue (HKLM,strKey & BS & strName,"Configuration",strValue)
   On Error GoTo 0

   'if Configuration value found
   If intErrNum = 0 And strValue <> "" Then

    strSubTitle = "HKLM\" & strKey & BS & strName & BS
    TitleLineWrite
    'output Configuration value
    oFN.WriteLine "Configuration = " & strValue

    'parse comma-delimited strValue into arAcc array
    StrParse2Unique strValue

   End If  'Configuration value exists?

  End If  'Session# sub-key found?

 End If  'HKLM...Accessibility sub-keys exist?


 'output arAcc members - unique accessibility tools
 strKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"

 'get the ATs sub-keys
 oReg.EnumKey HKLM, strKey, arSubKeys

 'if array populated
 If IsArray(arSubKeys) Then

  'for each unique app tool
  For Each strName In arAcc

   'for each ATs sub-key name
   For Each strSubKey In arSubKeys

    'if app tool = sub-key name
    If LCase(Trim(strName)) = LCase(Trim(strSubKey)) Then

     'find Description & StartExe values
     strValue1 = RtnValue (HKLM, strKey & BS & strSubKey, "Description", REG_SZ)
     strValue2 = RtnValue (HKLM, strKey & BS & strSubKey, "StartExe", REG_EXPAND_SZ)

     strFN = LCase(Fso.GetFileName(strValue2))  'find file name
     strCN = CoName(IDExe(strValue2))  'find CoName

     'no output if StartExe simple integer
     If IsNumeric(strValue2) Then Exit For

     'output title line
     strSubTitle = "HKLM\" & strKey & BS & strSubKey & BS
     TitleLineWrite

     strWarn = IWarn  'assume StartExe is not an allowed executable

     'empty strWarn if StartExe/CoName OK or StartExe empty
     For i = 0 To UBound(arAllowedNames)
      If (strFN = arAllowedNames(i) And strCN = MS) Or _
       strFN = "(empty string)" Then
       strWarn = "" : Exit For
      End If
     Next

     If strWarn <> "" Then flagIWarn = True

     'output data
     oFN.WriteLine "Description = " & strValue1 & vbCRLF &_
      strWarn & "StartExe = " & strValue2 & strCN

     Exit For  'arSubKey members

    End If  'arAcc member=ATs sub-key name?

   Next  'arSubKey member

  Next  'arAcc member

 End If  'is arSubKeys an array?

 'clean up
 strTitle = "" : strSubTitle = "" : intUB = 0
 ReDim arAllowedNames(0)

End If  'WVa/Wn7?

End If  'SecTest?




'#35. Keyboard Driver Filters

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

'prepare title line
strTitle = "Keyboard Driver Filters:"

Dim arMSValue  'Multi-String Value array
strOut = ""  'empty output string
flagInfect = False

'for W2K/WXP/WVa/Wn7
If strOS = "W2K" Or strOS = "WXP" Or strOS = "WVA" Or strOS = "WN7" Then

 strKey = "SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-BFC1-08002BE10318}"
 On Error Resume Next
  oReg.GetMultiStringValue HKLM,strKey,"UpperFilters",arMSValue
 On Error GoTo 0

 strOut = ""

 'if value exists
 If IsArray(arMSValue) Then

  'if array is not empty
  For Each strValue In arMSValue

   'reset warning prefix for each value
   strWarn = ""

   'if not default value
   If LCase(Trim(strValue)) <> "kbdclass" Then

    'toggle infection flag
    flagIWarn = True : strWarn = IWarn

   End If

   'for CoName, if no extension, look in Drivers
   If Fso.GetExtensionName(strValue) = "" Then
    strCN = CoName(strFPSF & "\Drivers\" & strValue & ".sys")
   Else  'use IDExe for CoName
    strCN = CoName(IDExe(strValue))
   End If  'extension?

   If strCN <> MS Then

    flagIWarn = True : strWarn = IWarn

   End If

   'if output string not empty, use leading comma
   strOut = StrOutSep (strOut, strWarn & strValue & strCN, ",")

  Next  'multi-string value element

  'output if ShowAll or warning embedded in output string
  If InStr(strOut,IWarn) > 0 Or flagShowAll then

   TitleLineWrite

   'prefix warning if any suspicious filter found
   If InStr(strOut,IWarn) > 0 Then strWarn = IWarn

   oFN.WriteLine vbCRLF & "HKLM\" & strKey & BS & vbCRLF &_
    strWarn & "UpperFilters = " & strOut

  End If  'kbdclass Or flagShowAll?

 Else  'arMSValue not returned

  If flagShowAll Then
   TitleLineWrite : oFN.WriteLine vbCRLF & "HKLM\" & strKey & BS & vbCRLF &_
     "UpperFilters = (value not found)"
  End If

 End If  'IsArray(arMSValue)?

End If  'W2K/WXP/WVa/Wn7?

strTitle = "" : strSubTitle = "" : strSubSubTitle = "" : strOut = ""

End If  'SecTest?




'#36. Print Monitors

intSection = intSection + 1

'execute section if not in testing mode or (in testing mode And this section selected for testing)
If Not flagTest Or (flagTest And SecTest) Then

Dim arPMon()
'assume monitor driver files don't exist
Dim flagMonDrvExist : flagMonDrvExist = False
'PrtProcs Path
Dim strPPP : strPPP = strFPSF & "\spool\prtprocs"
If strOS = "WME" Then strPPP = strFPWF & "\spool\printers"
Dim oPPF  'PrtProcs Folder object

If strOS = "NT4" Then
 ReDim arPMon(1,1)
 arPMon(0,0) = "Local Port" : arPMon(0,1) = "localmon.dll"
 arPMon(1,0) = "PJL Language Monitor" : arPMon(1,1) = "pjlmon.dll"
ElseIf strOS = "W2K" Or strOS = "WXP" Then
 ReDim arPMon(5,1)
 arPMon(0,0) = "BJ Language Monitor" : arPMon(0,1) = "cnbjmon.dll"
 arPMon(1,0) = "Local Port" : arPMon(1,1) = "localspl.dll"
 arPMon(2,0) = "PJL Language Monitor" : arPMon(2,1) = "pjlmon.dll"
 arPMon(3,0) = "Standard TCP/IP Port" : arPMon(3,1) = "tcpmon.dll"
 arPMon(4,0) = "USB Monitor" : arPMon(4,1) = "usbmon.dll"
 arPMon(5,0) = "Windows NT Fax Monitor" : arPMon(5,1) = "msfaxmon.dll"
ElseIf strOS = "WVA" Or strOS = "WN7" Then
 ReDim arPMon(5,1)
 arPMon(0,0) = "Local Port" : arPMon(0,1) = "localspl.dll"
 arPMon(1,0) = "Microsoft Shared Fax Monitor" : arPMon(1,1) = "FXSMON.DLL"
 arPMon(2,0) = "Standard TCP/IP Port" : arPMon(2,1) = "tcpmon.dll"
 arPMon(3,0) = "USB Monitor" : arPMon(3,1) = "usbmon.dll"
 arPMon(4,0) = "WSD Port" : arPMon(4,1) = "WSDMon.dll"
 arPMon(5,0) = "LPR Port" : arPMon(5,1) = "lprmon.dll"
ElseIf strOS = "WME" Then
 ReDim arPMon(0,1)
 arPMon(0,0) = "usbmon" : arPMon(0,1) = "usbmon.dll"
End If

strTitle = "Print Monitors:"
strKey = "System\CurrentControlSet\Control\Print\Monitors"
strSubTitle = SYCA("HKLM" & BS & strKey & BS)

'find all the subkeys
oReg.EnumKey HKLM, strKey, arSubKeys

'enumerate data if present
If IsArray(arSubKeys) Then

 'for each key
 For Each strSubKey In arSubKeys

  'set default values
  strCN = "" : flagAllow = False
  strOut = "" : flagInfect = False : strWarn = ""
  flagMonDrvExist = False

  'get the driver value
  On Error Resume Next
   intErrNum = oReg.GetStringValue (HKLM,strKey & BS & strSubKey,"Driver",strValue)
  On Error GoTo 0

  'if the driver value exists (exc for W2K!)
  If intErrNum = 0 And strValue <> "" Then

   flagMonDrvExist = True

   strCN = CoName(IDExe(strValue))

   'check for unauthorized driver in \spool\prtprocs

   If Fso.FolderExists(strPPP) Then

    flagInfect = False  'monitor drivers not in prtprocs
    Set oPPF = Fso.GetFolder(strPPP)
    PrtProcPM Fso.GetFileName(strValue), oPPF
    If flagInfect Then strWarn = IWarn

   Else  'prtprocs folder not found

    flagIWarn = True : flagInfect = True : strWarn = IWarn
    strOut = SP & strPPP & " not found!"

   End If

   'check for allowed drivers
   If strOS <> "W98" Then

    'set flagAllow if subkey name & drive name are on approved list
    For j = 0 To UBound(arPMon,1)

     If LCase(strSubKey) = LCase(arPMon(j,0)) And _
      LCase(strValue) = LCase(arPMon(j,1)) And _
      strCN = MS Then
       flagAllow = True : Exit For
     End If

    Next  'arPMon

   End If  'strOS?

   'output if driver in prtprocs directory or unapproved or ShowAll
   If flagInfect Or Not flagAllow Or flagShowAll Then

    TitleLineWrite
    oFN.WriteLine strWarn & strSubKey & "\Driver = " & strValue &_
     strCN & strOut

   End If  'output?

  End If  'driver value exists?

 Next  'Monitors subkey

Else  'print monitor subkeys array not found

 strSubTitle = strSubTitle & vbCRLF & "(no drivers found)"
 TitleLineWrite

End If  'Monitors subkeys array exist

If flagShowAll Then TitleLineWrite

strTitle = "" : strSubTitle = "" : strSubSubTitle = ""

'recover array memory
ReDim arPMon(0,0)

End If  'SecTest?


'run closing sub
SRClose


'clean up
Set oReg=Nothing
Set Fso=Nothing
Set Wshso=Nothing




Sub SRClose

'find the number of seconds spent replying to popups
Dim datPUBsec : datPUBsec = datPUB1 + datPUB2
'find the words for the message box duration
Dim strPUBSec
Dim strOut
If flagShowAll Or flagSupp Or flagOut = "C" Then
 strPUBsec = ""
ElseIf datPUBsec < 2 Then
 strPUBsec = ", including " & datPUBsec & " second for message boxes"
Else
 strPUBsec = ", including " & datPUBsec & " seconds for message boxes"
End if

'form the run time phrase
Dim strRunTime : strRunTime = " (total run time: " &_
 DateDiff("s",datLaunch,Now) & " seconds" & strPUBsec & ")"
Dim intClosePUBSec  'script close announcement popup display seconds
Dim strBody : strBody = ""
Dim strSpacer : strSpacer = vbCRLF
Dim strHeader : strHeader = vbCRLF & vbCRLF & String(10,"-") &_
 " (launch time: " & FmtDate(datLaunch) & " " & FmtHMSFtr(datLaunch) & ")"
Dim strFooter : strFooter = vbCRLF & String(10,"-") &_
 strRunTime

'explain <<!>> & <<H>> symbols if present
'precede HWarn symbol by new line if IWarn also present
If flagIWarn And flagHWarn Then strSpacer = ""

If flagIWarn Then strBody = strBody & vbCRLF & "<<!>>: " &_
 "Suspicious data at a malware launch point." & vbCRLF

If flagHWarn Then strBody = strBody & strSpacer & "<<H>>: " &_
 "Suspicious data at a browser hijack point." & vbCRLF

If Not flagShowAll Then
 strBody = strBody &_
 vbCRLF & "+ This report excludes default entries except where indicated." &_
 vbCRLF & "+ To see *everywhere* the script checks and *everything* it finds," &_
 vbCRLF & "  launch it from a command prompt or a shortcut with the -all parameter."
 If Not flagSupp Then
  strBody = strBody &_
  vbCRLF & "+ To search all directories of local fixed drives for DESKTOP.INI" &_
  vbCRLF & "  DLL launch points, use the -supp parameter or answer " & DQ & "No" & DQ &_
  " at the" & vbCRLF & "  first message box and " & DQ & "Yes" & DQ &_
  " at the second message box."
 Else  'flagSupp=True
  strBody = strBody &_
  vbCRLF & "+ The search for DESKTOP.INI DLL launch points on all local fixed drives" &_
  vbCRLF & "  took " & strDTITime & "."
 End If
Else  'flagShowAll=True
 strHeader = vbCRLF & vbCRLF & "--" & strRunTime : strFooter = ""
End If

oFN.WriteLine strHeader & strBody & strFooter

oFN.Close : Set oFN=Nothing

'inform user that script is complete
If flagOut = "W" Then

 intClosePUBSec = 20 : If flagTest Then intClosePUBSec = 1

 'include path if report file directory specified via cmd-line parameter
 If flagDirArg Then

  strOut = "All Done! The results are in the file:" & vbCRLF & vbCRLF &_
   strFN

 Else  'directory not specified via cmd-line parameter

  strOut = "All Done! The results are in the file:" & vbCRLF & vbCRLF &_
   strFNNP & vbCRLF & vbCRLF & "This file is in the same directory as the script."

 End if  'report file path?

 Wshso.PopUp strOut,intClosePUBSec,"Silent Runners R" & strRevNo & " Complete", _
  vbOKOnly + vbInformation + vbSystemModal

Else  'console output

 'include path if report file directory specified via cmd-line parameter
 If flagDirArg Then

  strOut = "Silent Runners R" & strRevNo & " is done! The results " &_
  "are in the file:" & vbCRLF & vbCRLF & strFN

 Else  'directory not specified via cmd-line parameter

  strOut = "Silent Runners R" & strRevNo & " is done! The results " &_
  "are in the file:" & vbCRLF & vbCRLF & strFNNP & vbCRLF & vbCRLF &_
  "This file is in the same directory as the script."

 End If  'report file path?

 WScript.Echo strOut

End If  'flagout?

End Sub




'YYYY-MM-DD
Function FmtDate (datIn)

 FmtDate = Year(datIn) & "-" & Right("0" & Month(datIn),2) & "-" &_
  Right("0" & Day(datIn),2)

End Function




'hh.mm.ss for report title
Function FmtHMS (datIn)

 FmtHMS = Right("0" & Hour(datIn),2) & "." & Right("0" & Minute(datIn),2) &_
  "." & Right("0" & Second(datIn),2)

End Function




'hh:mm:ss for report footer
Function FmtHMSFtr (datIn)

 FmtHMSFtr = Right("0" & Hour(datIn),2) & ":" & Right("0" & Minute(datIn),2) &_
  ":" & Right("0" & Second(datIn),2)

End Function




'enumerate Names and Types under a key
Sub EnumNT (hexHive,strRunKey,arNames,arType)

Dim intUB, intErrNum, intErrNum1, i

flagNames = False

'find all the names in the key
intErrNum = oReg.EnumValues (hexHive, strRunKey, arNames, arType)

'excludes W2K/WXP/WVa/Wn7 with no name/value pairs
If intErrNum = 0 And IsArray(arNames) Then

 'get array UBound
 intUB = UBound(arNames)

 'excludes W98/WMe/NT4 with no name/value pairs
 If intUB >= 0 Then flagNames = True

End If  'names array exists?

End Sub




'return value given name & value Type, toggle flag if value found
Function RtnValue (hexHive, strKey, strName, intType)

flagValueFound = False : strAbbrevValue = ""

'value as string/integer/array, counter, string variable, error number
Dim strFValue, intFValue, arFValue, i, strFMsg, intFErrNum

Select Case intType

 'string value
 Case REG_SZ

  'return the string-type value
  On Error Resume Next
   intFErrNum = oReg.GetStringValue (hexHive,strKey,strName,strFValue)
  On Error GoTo 0

  If intFErrNum = 0 Then
   If strFValue = "" Then
    strAbbrevValue = "" : strFValue = "(empty string)"
   Else
    strAbbrevValue = strFValue : flagValueFound = True
   End If  'value empty?
    RtnValue = strFValue
  Else
   strAbbrevValue = "" : RtnValue = "(value not set)"
  End If  'value set?

 'expandable-string value
 Case REG_EXPAND_SZ

  'return the expanded string-type value
  On Error Resume Next
   intFErrNum = oReg.GetExpandedStringValue (hexHive,strKey,strName,strFValue)
  On Error GoTo 0

  If intFErrNum = 0 Then
   If strFValue = "" Then
    strAbbrevValue = "" : strFValue = "(empty string)"
   Else
    strAbbrevValue = strFValue : flagValueFound = True
   End If  'value empty?
    RtnValue = strFValue
  Else
    strAbbrevValue = "" : RtnValue = "(value not set)"
  End If  'value set?

 'binary value
 Case REG_BINARY

  'return the binary-type value as array
   On Error Resume Next
    intFErrNum = oReg.GetBinaryValue (hexHive,strKey,strName,arFValue)
   On Error GoTo 0

  If intFErrNum = 0 And IsArray(arFValue) Then

   If UBound(arFValue) >= 0 Then
    'delimit every two-bytes by space
    strFMsg = ""
    For i = 0 To UBound(arFValue)
     strFMsg = strFMsg & Right("00" & CStr(Hex(arFValue(i))),2) & " "
    Next
    strAbbrevValue = strFMsg : strFMsg = "hex:" & RTrim(strFMsg) : flagValueFound = True
   Else  'UBound(arFValue) = -1
    strAbbrevValue = "" : strFMsg = "(value not set)"
   End If  'UBound >= 0?
   RtnValue = strFMsg
  Else
   strAbbrevValue = "" : RtnValue = "(value not set)"
  End If  'value array exists?

 '4-byte (32-bit) value
 Case REG_DWORD

  'return the DWORD-type value
  On Error Resume Next
   intFErrNum = oReg.GetDWORDValue (hexHive,strKey,strName,intFValue)
  On Error GoTo 0

  If intFErrNum = 0 Then
   flagValueFound = True
   strAbbrevValue = CStr(Hex(intFValue))
   RtnValue = "dword:0x" & Right("00000000" & CStr(Hex(intFValue)),8)
  Else
   strAbbrevValue = "" : RtnValue = "(value not set)"
  End If

 'multiple-string value
 Case REG_MULTI_SZ

  'return the multiple-string-type value
  On Error Resume Next
   intFErrNum = oReg.GetMultiStringValue (hexHive,strKey,strName,arFValue)
  On Error GoTo 0

  If intFErrNum = 0 And IsArray(arFValue) Then
   If UBound(arFValue) >= 0 Then
    flagValueFound = True
    'delimit every string by "|"
    strFMsg = ""
    For i = 0 To UBound(arFValue)
     strFMsg = strFMsg & arFValue(i) & "|"
    Next

   Else  'UBound(arFValue) = -1
    strAbbrevValue = "" : strFMsg = "(value not set)|"  'append "|" for later deletion
   End If  'UBound >= 0?
   strFMsg = Left(strFMsg,Len(strFMsg)-1)  'lop off trailing "|"
   strAbbrevValue = strFMsg : RtnValue = strFMsg
  Else
   strAbbrevValue = "" : RtnValue = "(value not set)"
  End If  'value array exists?

 '8-byte (64-bit) value
 Case REG_QWORD

  'return the QWORD-type value
  On Error Resume Next
   intFErrNum = oReg.GetQWORDValue (hexHive,strKey,strName,intFValue)
  On Error GoTo 0

  If intFErrNum = 0 Then
   flagValueFound = True
   strAbbrevValue = CStr(Hex(intFValue))
   RtnValue = "hex:0x" & Right("0000000000000000" & CStr(Hex(intFValue)),16)
  Else
   strAbbrevValue = "" : RtnValue = "(value not set)"
  End If

 Case Else

  'admit we don't know what it is
  strAbbrevValue = "" : RtnValue = "(unknown data type)"

End Select  'data type

End Function




'return Type as string given Type as integer
Function RtnType (intType)

Select Case intType

 'string value
 Case REG_SZ

  RtnType = "REG_SZ"

 'expandable-string value
 Case REG_EXPAND_SZ

  RtnType = "REG_EXPAND_SZ"

 'binary value
 Case REG_BINARY

  RtnType = "REG_BINARY"

 '4-byte value
 Case REG_DWORD

  RtnType = "REG_DWORD"

 'multiple-string-type value
 Case REG_MULTI_SZ

  RtnType = "REG_MULTI_SZ"

 Case REG_QWORD

  RtnType = "REG_QWORD"

 'any other type
 Case Else

  RtnType = "(unknown data type)"

End Select

End Function




'write name/value pair to file
Function WriteValueData (strName, strValue, intType, strWarn)

Dim strOQEC  'Optionally Quote-Enclosed Comment

If intType = REG_SZ And LCase(strName) <> "title" Then
 strOQEC = strValue & CoName(IDExe(strValue))
Else
 strOQEC = strValue
End If

'output the name and value
If strName = "" Then
  oFN.WriteLine strWarn & "(Default) = " & strOQEC
Else  'name is non-empty string
 oFN.WriteLine strWarn & strName & " = " & strOQEC
End If

End Function




'compare registry value to accepted value and output
'hexHive, registry key, value name, accepted value, Special Handling label, CoName output flag
'strSH values: "ui" (userinit.exe[,]), "lrp" (load/run)
'any value output if accepted value = "none", CoName not output if flagCoName = False
Sub RegDataChk_v2 (cHive, strKey, strName, strAccVal, strSH, flagCoName)

strSH = LCase(strSH)  'put special handler flag into lower case

Dim intType, strWarn, strValue
intType = 0 : strWarn = "" : strValue = ""  'initialize variables

'find value names & types
EnumNT cHive,strKey,arNames,arType

'if names exist, check for strName
If flagNames Then

 'for every name
 For i = 0 To UBound(arNames)

  'if target name found
  If LCase(arNames(i)) = LCase(strName) Then

   intType = arType(i)  'store type
   strValue = RtnValue (cHive, strKey, arNames(i), intType)  'find value

   'set strAccVal = EnumNT output if value empty or not set
   If strAccVal = "" And (strValue = "(empty string)" Or _
    strValue = "(value not set)") Then strAccVal = strValue

   'for ui, use string + comma-appended string as reference
   If strSH = "ui" Then

    'toggle IWarn if both value /comma-appended value not accepted
    If LCase(Trim(strValue)) <> LCase(strAccVal) And _
     LCase(Trim(strValue)) <> LCase(strAccVal) & "," Then
     flagIWarn = True : strWarn = IWarn

    End If  'exception found?

   'warn if no value allowed Or value <> allowed,
   ElseIf LCase(strAccVal) = "none" Or LCase(Trim(strValue)) <> LCase(strAccVal) Then

    flagIWarn = True : strWarn = IWarn

   End If  'exception found?

   Exit For  'exit arNames loop

  End If  'target name found?

 Next  'arNames member

 'if type not set, name wasn't found
 If intType = 0 Then strValue = "(name not found)"

 'if output needed
 If strWarn <> "" Or flagShowAll Then

  TitleLineWrite

  'use LRParse for certain special handling fields
  If intType = REG_MULTI_SZ Or strValue = "(empty string)" Or _
   strValue = "(value not set)" Or strValue = "(name not found)" Then

   oFN.WriteLine strWarn  & strName & " = " & strValue

  Else  'not REG_MULTI_SZ And value found

   'for CoName output
   If flagCoName Then

    'if "lrp" or "ui" special handling, use LRParse
    If strSH = "lrp" Or strSH = "ui" Then
     oFN.WriteLine strWarn & strName & " = " & strValue & LRParse(strValue)
    Else  'for any other special handling flags, use CoName
     oFN.WriteLine strWarn & strName & " = " & strValue & CoName(IDExe(strValue))
    End If

   Else  'no CoName output

    oFN.WriteLine strWarn & strName & " = " & strValue

   End If  'flagCoName?

  End If  'REG_MULTI_SZ or no value found?

 End If  'output needed?

ElseIf flagShowAll Then  'no names under key

 TitleLineWrite
 oFN.WriteLine strName & " = (name not found)"

End If  'names exist?

End Sub




'find a key's default value and compare to allowed string
Sub ChkDefaultValue (strKey,strAllowedValue)

'error number, value
Dim intErrNum, strValue
'initialize warning string
Dim strWarn : strWarn = ""

'find default value
On Error Resume Next
 intErrNum = oReg.GetStringValue (HKLM,strKey,"",strValue)
On Error GoTo 0

'if default value found
If intErrNum = 0 And strValue <> "" Then

 'toggle warnings if default value not allowed
 If LCase(Trim(strValue)) <> LCase(strAllowedValue) Then
  strWarn = IWarn : flagIWarn = True
 End If

 'if output needed
 If strWarn <> "" Or flagShowAll Then
  'output
  TitleLineWrite
  oFN.WriteLine strWarn & "(Default) = " & strValue
 End If

End If

End Sub




'enumerate a key's names and, for names matching those in a dictionary,
'find the values and compare to allowed strings stored as dictionary items
'if the values don't match the allowed strings and a flag is set,
'display the value at the unallowed location
Sub ChkNameValues (strKey, dictNV, flagResolveValue)

'error numbers
Dim intErrNum, intErrNum1, intErrNum2
'name/value type arrays, Dictionary associative array, single key
Dim arNames, arType, arDictKeys, strDictKey
'key, name, value x 2, output warning, output string
Dim strKey1, strName, strValue, strValue1, strWarn, strOut
'loc'n of SYS:/USR:
Dim intSYS, intUSR

'enumerate key names
oReg.EnumValues HKLM, strKey, arNames, arType

'if name array found
If IsArray(arNames) Then

 'put dictionary keys in array
 arDictKeys = dictNV.Keys

 'for each name under strKey
 For Each strName In arNames

  'intialize variables
  strWarn = "" : strOut = ""

  'find value
  On Error Resume Next
   intErrNum1 = oReg.GetStringValue (HKLM,strKey,strName,strValue)
  On Error GoTo 0

  'if value exists
  If intErrNum1 = 0 And strValue <> "" Then

   'for every dictionary key
   For Each strDictKey In arDictKeys

    'if dictionary key = name
    If LCase(Trim(strDictKey)) = LCase(Trim(strName)) Then

     'if dictionary key's item <> name's value
     If LCase(dictNV.Item(strDictKey)) <> LCase(Trim(strValue)) Then

      'toggle warnings
      strWarn = IWarn : flagIWarn = True

       'if need to resolve name's value
       If flagResolveValue Then

        'look for "SYS:" and "USR:"
        intSYS = InStr(LCase(Trim(strValue)),"sys:")
        intUSR = InStr(LCase(Trim(strValue)),"usr:")
        'extract string beyond "SYS:" or "USR:"
        strKey1 = Mid(Trim(strValue),5)

        If intSYS = 1 Then  'if "SYS:" found in value

         'resolve value in HKLM\SOFTWARE
         On Error Resume Next
          intErrNum2 = oReg.GetStringValue (HKLM,"SOFTWARE\" & strKey1,strName,strValue1)
          'form strOut if resolved value found
         On Error GoTo 0
         If intErrNum2 = 0 And strValue1 <> "" Then _
          strOut = vbCRLF & strWarn & "HKLM\SOFTWARE\" & strKey1 & BS & strName &_
           " = " & strValue1

        ElseIf intUSR = 1 Then  'if "USR:" found in value

         'resolve value in HKCU\Software
         On Error Resume Next
          intErrNum2 = oReg.GetStringValue (HKCU,"Software\" & strKey1,strName,strValue1)
         On Error GoTo 0
         'form strOut if resolved value found
         If intErrNum2 = 0 And strValue1 <> "" Then _
          strOut = vbCRLF & strWarn & "HKCU\Software\" & strKey1 & BS & strName &_
           " = " & strValue1

        End If  'SYS: or USR: in value?

       End If  'resolver flag set?

     End If  'dictionary key's item <> name's value?

     'if output necessary
     If LCase(dictNV.Item(strDictKey)) <> LCase(Trim(strValue)) Or flagShowAll Then

      'output & exit For
      TitleLineWrite
      oFN.WriteLine strWarn & strName & " = " & strValue & strOut
      Exit For

     End If  'output necessary?

    End If  'dictionary key = name?

   Next  'dictionary key

  End If  'strValue exists?

 Next  'strKey name

End If  'name array found?

End Sub




'set NoDriveTypeAutoRun flag
Function NDTAR (cHive, flagValueExists, flagFDEnabled)

'DWORD or BINARY value, binary value array, error numbers x 2, hive name as string
Dim hVal, arBVal, intErrNum1, intErrNum2, strHive

strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

On Error Resume Next
 intErrNum1 = oReg.GetDWORDValue(cHive,strKey,"NoDriveTypeAutoRun",hVal)
On Error GoTo 0

'if cHive NoDriveTypeAutoRun DWORD value exists
If intErrNum1 = 0  Then

 flagValueExists = True

 'if autorun for fixed drives is disabled, set flag
 If (hVal And 8) = 8 Then flagFDEnabled = False

End If

On Error Resume Next
 intErrNum2 = oReg.GetBinaryValue(cHive,strKey,"NoDriveTypeAutoRun",arBVal)
On Error GoTo 0

'if cHive NoDriveTypeAutoRun BINARY value exists
If intErrNum2 = 0 Then

 'UBound = -1 if value not set (zero-length binary value)
 If UBound(arBVal) = -1 Then

  'if OS = W2K/WXP SP0/1, "value not set" interpreted by OS as
  '0 for NDTAR instead of null!
  If strOS = "W2K" Or strOS = "WXP" Then
   flagValueExists = True
  End If  'W2K/WXP?

 Else 'UBound <> -1, so value set

  flagValueExists = True : hVal = 0

  'binary value retrieved as array in increments of 16^2
  For i = 0 To UBound(arBVal)
   hVal = hVal + arBVal(i) * 256^i
  Next

  'if autorun for fixed drives is disabled, set flag
  On Error Resume Next
   If (hVal And 8) = 8 Then flagFDEnabled = False
   intErrNum = Err.Number : Err.Clear
  On Error GoTo 0

  If intErrNum <> 0 Then
   TitleLineWrite
   strHive = "HKCU\"
   If cHive = HKLM Then strHive = "HKLM\"
   oFN.WriteLine vbCRLF & SOCA(strHive & strKey & BS & vbCRLF &_
    "NoDriveTypeAutoRun = ** WARNING -- corrupt BINARY value! **")
  End If

 End If  'UBound = -1?

End If  'NoDriveTypeAutoRun value exists?

End Function




'detect if autorun disabled for individual drives
Function NDAR (cHive, flagValueExists)

'DWORD or BINARY value, binary value array, error numbers x 2, hive name as string
Dim hVal, arBVal, intErrNum1, intErrNum2, strHive

strKey = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

On Error Resume Next
 intErrNum1 =  oReg.GetDWORDValue(cHive,strKey,"NoDriveAutoRun",hVal)
On Error GoTo 0

'if cHive NoDriveAutoRun DWORD value exists
If intErrNum1 = 0 Then

 flagValueExists = True

 'for every fixed disk
 For i = 0 To UBound(arFixedDisks,2)

  'if autorun for fixed drive is disabled, set flag
  If (hVal And arFixedDisks(1,i)) = arFixedDisks(1,i) Then

   arFixedDisks(2,i) = False

  End If  'autorun disabled for this drive?

 Next  'fixed disk

End If

On Error Resume Next
 intErrNum2 = oReg.GetBinaryValue(cHive,strKey,"NoDriveAutoRun",arBVal)
On Error GoTo 0

'if cHive NoDriveAutoRun BINARY value exists
If intErrNum2 = 0 Then

 'UBound = -1 if value not set (zero-length binary value)
 If UBound(arBVal) = -1 Then

  'if OS = W2K/WXP SP0/1, "value not set" interpreted by OS as
  '0 instead of null!
  If strOS = "W2K" Or strOS = "WXP" Then

   flagValueExists = True

   'set all NDAR flags to True
   For i = 0 To UBound(arFixedDisks,2)
    arFixedDisks(2,i) = True
   Next

  End If  'W2K/WXP?

 Else  'UBound <> -1, so value set

  flagValueExists = True

  hVal = 0

  'binary value retrieved as array in increments of 16^2
  For i = 0 To UBound(arBVal)
   hVal = hVal + arBVal(i) * 256^i
  Next

  'for every fixed disk
  For i = 0 To UBound(arFixedDisks,2)

   On Error Resume Next
    'if autorun for the fixed disk is disabled, set flag
    If (hVal And arFixedDisks(1,i)) = arFixedDisks(1,i) Then
     arFixedDisks(2,i) = False
     intErrNum = Err.Number : Err.Clear
    End If
   On Error GoTo 0

   If intErrNum <> 0 Then
    strHive = "HKCU\"
    If cHive = HKLM Then strHive = "HKLM\"
    TitleLineWrite
    oFN.WriteLine vbCRLF & SOCA(strHive & strKey & BS & vbCRLF &_
     "NoDriveAutoRun = ** WARNING -- corrupt BINARY value! **")
    Exit For
   End If

  Next  'fixed disk

 End If  'hive NoDriveAutoRun value set?

End If  'hive NoDriveAutoRun value exists?

End Function




'INI/INF-file parser
Function IniInfParse (strInput, strVerb, strEquiv, strDisk)

Dim strOutput  'report line
Dim strWarn : strWarn = ""  'warning string
Dim strExe : strExe = ""  'executable after "="
Dim strLFN : strLFN = ""  'screen saver LFN
Dim intEqu

'if verb is first non-space chars (if line is populated)
If Left(LCase(LTrim(strInput)),Len(strVerb)) = strVerb Then

 'find pos'n of equals sign
 intEqu = InStr(strInput,"=")

 'find executable statement after equals sign
 strExe = Trim(Mid(strInput,intEqu+1))

 'if chrs to right of equals sign different from argument or ShowAll
 If (LCase(strExe) <> strEquiv) Or flagShowAll Then

  'fill warning string if chrs to right of equals sign different from argument
  If LCase(strExe) <> strEquiv And strEquiv <> "anything" Then
   strWarn = IWarn : flagIWarn = True
  End If

  'concatenate line for load or run
  If LCase(strVerb) = "load" Or LCase(strVerb) = "run" Then

   strOutput = strWarn & strInput & LRParse(strExe)

  'concatenate line for open or shellexecute
  ElseIf LCase(strVerb) = "open" Or LCase(strVerb) = "shellexecute" Then

   strOutput = strWarn & strDisk & "\AUTORUN.INF -> " &_
    strInput & CoName(IDExe(strDisk & BS & strExe))

  'if screensaver = None then no line exists in INI-file
  'if flagShowAll, nothing will be written since no line exists
  ElseIf LCase(strVerb) = "scrnsave.exe" Then

   'get screen saver LFN if file exists
   If Fso.FileExists(strExe) Then

    'create (but don't save) shortcut
    Dim oSC : Set oSC = Wshso.CreateShortcut("getLFN.lnk")
    'set & retrieve target path
    oSC.TargetPath = strExe
    strLFN = Fso.GetFile(oSC.TargetPath).Name
    Set oSC=Nothing

    'set up LFN string if SFN <> LFN
    If LCase(strLFN) = LCase(Fso.GetFileName(strExe)) Then
     strLFN = ""
    Else
     strLFN = " (" & strLFN & ")"
    End If

   End If  'screen saver file exists?

   strOutput = strWarn & strInput & strLFN & CoName(IDExe(strExe))

  'concatenate line for all other verbs
  Else

   strOutput = strWarn & strInput & LRParse(strExe)

  End If  'load/run, open/shellexecute, scrnsave.exe, other?

  TitleLineWrite : oFN.WriteLine strOutput

 End If  'verb populated?

End If  'line populated

End Function




'trim the parameters from a string to isolate the executable and
'then locate the executable on the hard disk
Function IDExe (strPath)

'check for empty string
If IsNull(strPath) Or strPath = "" Then
 IDExe = "file not found" : Exit Function
End If

'work path: trimmed, lower case, expanded env strings
Dim strPWk : strPWk = Trim(LCase(Wshso.ExpandEnvironmentStrings(strPath)))

Dim intFS  'forward slash pos'n

'check for "res://"
If Left(strPWk,6) = "res://" Then

 'look for forword slash after "res://"
 intFS = InStr(7,strPWk,"/",1)
 'if no trailing fs, annex one's position at end of string
 If intFS = 0 Then intFS = Len(strPWk) + 1
 'extract string between "res://" and trailing fs
 strPWk = Mid(strPWk,7,intFS-7)

End If  'string starts with "res://"?

If Fso.FileExists(strPWk) Then
 IDExe = Fso.GetFile(strPWk).Path : Exit Function
End If  'as-is?

'dissect input string

'work path & TmpExe strings, loc'n of decimal pt, second quote, backslash, counter
Dim strTEx, intDP, int2Q, intBS, i
Dim flagFileFound : flagFileFound = False  'TRUE if file found in called function
Dim flagSpaceExists : flagSpaceExists = True  'FALSE if no space in work path
'Executable Extension array
Dim arExeExt : arExeExt = Array (".exe", ".com", ".cmd", ".bat", ".pif", ".dll")

'look for leading double quote, embedded " /", " """ (parameter prefixes)
If Left(strPWk,1) = DQ Then
 'if find it, then look for second quote
 int2Q = InStr(2, strPWk, """")
 'if find it, reset the path string to what was between the quotes
 If int2Q > 0 Then strPWk = Trim(Mid(strPWk, 2, int2Q - 2))
'look for embedded " /"
ElseIf InStr(strPWk," /") > 0 Then
 'if find it, reset the path string
 strPWk = Trim(Mid(strPWk,1,InStr(strPWk," /")-1))
'look for embedded space + double quote
ElseIf InStr(strPWk," """) > 0 Then
 'if find it, reset the path string
 strPWk = Trim(Mid(strPWk,1,InStr(strPWk," """)-1))
End If

Do While flagSpaceExists

 'look for trailing dot & backslash
 intDP = InStrRev(strPWk,".")
 intBS = InStrRev(strPWk,BS)

 'if dot found And dot after backslash And string contains extension
 If (intDP > 0) And (intDP > intBS) And (intDP < Len(strPWk)) Then

  'look for entire string on hard disk
  strTEx = WSL(strPWk, flagFileFound)

  'if found, return it
  If flagFileFound Then
   IDExe = strTEx : Exit Function
  End if

 Else  'either dot not found Or dot in string Or string has no extension

  'try adding executable extension
  For i = 0 To UBound(arExeExt)

   'look for string on hard disk
   strTEx = WSL(strPWk & arExeExt(i), flagFileFound)

   'if found, return it with executable extension appended
   If flagFileFound Then
    IDExe = strTEx : Exit Function
   End if

  Next  'executable extension

 End If  'dot found And dot after BS And string has extension?

 'trim chrs after space
 If InStrRev(strPWk," ") = 0 Then
  flagSpaceExists = False
 Else
  strPWk = Trim(Left(strPWk,InStrRev(strPWk," ") - 1))
 End If

Loop  'flagSpaceExists

'last chance: look for AppPath of space-less executable

strPWk = Trim(AppPath(strPWk))
strTEx = WSL(strPWk,flagFileFound)

If flagFileFound Then
 IDExe = strTEx
Else
 IDExe = "file not found"
End if

End Function




'WinSysLocate
Function WSL (strIn, logFound)

'set default results
WSL = strIn : logFound = False

'if strIn exists, exit
If Fso.FileExists(strIn) Then

 WSL = Fso.GetFile(strIn).Path
 logFound = True

'if strIn doesn't contain drive or UNC network path
ElseIf InStr(strIn,":") = 0 And InStr(strIn,"\\") <> 1 Then

 'check for file in Windows directory
 If Fso.FileExists(strFPWF & BS & strIn) Then

  WSL = strFPWF & BS & strIn : logFound = True

 'check for file in System directory
 ElseIf Fso.FileExists(strFPSF & BS & strIn) Then

  WSL = strFPSF & BS & strIn : logFound = True

 'check for file in SysWOW64 directory
 ElseIf Fso.FileExists(strFPWF & "\SysWOW64\" & strIn) Then

  WSL = strFPWF & "\SysWOW64\" & strIn : logFound = True

 End If  'prefixed strIn exists?

End If  'strIn contains path?

End Function




'find company name in existing file
Function CoName (strFN)

If strFN = "file not found" Or IsNull(strFN) Or strFN = "" _
 Or Not Fso.FileExists(strFN) Then
 CoName = " [file not found]"
 Exit Function
End If

'WMI file object, co-name, error number, working file name
Dim oFile, strMftr, intErrNum, strFNWk

'R44 -- removed StringFilter added in R40 -- findable Unicode file
' name added "unwritable string", which automatically threw a
' WMI GetObject Error
strFNWk = strFN

'if there are already escaped backslashes, unescape them
If InStr(strFNWk,"\\") <> 0 Then strFNWk = Replace(strFNWk,"\\",BS)
'now reescape all of them
strFNWk = Replace(strFNWk,BS,"\\")

'get the file object with filename delimited by double quotes
'(couldn't get single quotes to work with single quote embedded in path)
On Error Resume Next
 Set oFile = GetObject("winmgmts:\root\cimv2").Get _
  ("CIM_DataFile.Name=""" & strFNWk & """")
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0
If intErrNum <> 0 Then
 CoName = " [** WMI GetObject error **]"
 Exit Function
End If

'find the co-name
strMftr = oFile.Manufacturer

Set oFile=Nothing

 'if null, say so
 If IsNull(strMftr) Then

  CoName = " [null data]"

 'if empty, say so
 ElseIf strMftr = "" Then

  CoName = " [empty string]"

 'if some company, say it
 Else

  'if MS, say it with 2 letters
  'Chr(160) spacing chr used in WVa 64-bit dfshim.dll shell extension
  If strMftr = "Microsoft Corporation" Or strMftr = "Microsoft Corp." Or _
   strMftr = "Microsoft" & Chr(160) & "Corporation" Then

   CoName = MS

  'if some other company, provide all the data, which may take up several lines
  Else

   CoName = " [" & Replace(strMftr,Chr(13) & Chr(10),Space(1)) & "]"

  End If  'MS or not?

 End If  'null, mt, MS or not?

End Function




'SCRipts.Ini-File Parser
'file name to open, action for which scripts must be parsed
Function ScrIFP (strValue, strAction)

'form scripts.ini path\FileName
Dim strScrFN : strScrFN = strValue & "\scripts.ini"
'default path
Dim strDefPath : strDefPath = ""

'error number, line read from file, pos'n of CmdLine & equals sign,
'parameter string, line intro ("arrow") string
Dim intErrNum, strLine, intCS, intEq, strParam, strArrow
Dim strSC : strSC = ""  'script command
Dim intSN : intSN = 0  'script number
Dim strCmd : strCmd = ""  'command string
Dim flagSection : flagSection = False  'True if in strAction section
Dim flagActionWritten : flagActionWritten = False  'True if Action written once
Dim intActL : intActL = Len(strAction)  'action length (used for spacing of output)

'open the SCRIPTS.INI file For Reading
On Error Resume Next
 Dim oSI : Set oSI = Fso.OpenTextFile(strScrFN, 1, False,-1)
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if couldn't open file, output a warning & quit
If intErrNum <> 0 Then
 TitleLineWrite
 oFN.WriteLine "WARNING! Insufficient permission to read " &_
  DQ & strScrFN & DQ
 Exit Function
End If

'for every line of file
Do Until oSI.AtEndOfStream

 strLine = oSI.ReadLine

 'if know already in right section
 If flagSection Then

  'exit if find beginning of next section
  If InStr(strLine, "[") Then Exit Do

  '[Logon]
  '0CmdLine=path\filename.ext
  '0Parameters=

  'find pos'n of equals sign
  intEq = InStr(strLine,"=")

  'if equals sign found in the line
  If intEq > 0 Then

   'output saved info if the script number has changed
   If intSN <> FLN(strLine) Then

    TitleLineWrite
    strArrow = strAction & " -> launches: "
    If flagActionWritten = True Then strArrow = Space(intActL+2) & " -> launches: "

    'output script command, reset script command & saved script number
    oFN.WriteLine strArrow & strSC & CoName(IDExe(strCmd))
    strSC = "" : strCmd = "" : flagActionWritten = True
    intSN = FLN(strLine)

   End If  'new script number?

   'current line is cmdline
   If InStr(LCase(strLine), "cmdline") > 0 Then

    'if cmdline doesn't contain backslash, form script path from
    'function parameters
    If InStr(strLine,BS) = 0 Then strDefPath = strValue & BS & strAction & BS

    'add script command to command string
    strSC = strDefPath & Mid(strLine, intEQ + 1) & strSC
    strCmd = strDefPath & Mid(strLine, intEQ + 1)  'store cmdline field for co-name id

   'if parameters line
   ElseIf InStr(LCase(strLine), "parameters") > 0 Then

    'extract parameters string
    strParam = Mid(strLine, intEq + 1)

    'add non-empty parameters command to command string
    If Trim(strParam) <> "" Then strSC = strSC & " " & strParam

   End If  'line is cmdline or parameter

  End If  '"=" in this line

 End If  'inside action section

 'if action found in current line, set flag to True
 If InStr(LCase(strLine), LCase(strAction)) > 0 Then flagSection = True

Loop  'next line in SCRIPTS.INI

oSI.Close : Set oSI=Nothing

'if a script was located, output last script command found
If strSC <> "" Then

 strArrow = strAction & " -> launches: "
 If flagActionWritten = True Then strArrow = Space(intActL+2) & " -> launches: "
 TitleLineWrite
 oFN.WriteLine strArrow & strSC & CoName(IDExe(strCmd))

End If  'script located?

End Function




'Find Leading Number
Function FLN (strLine)

'save the input in a trimmed work variable
Dim strWork : strWork = LTrim(strLine)
'initialize the output number
Dim intNumber : intNumber = 0

'counter, single character
Dim i, str1C
'find length of work variable
Dim intLen : intLen = Len(strWork)

'for the length of the work variable
For i = 1 To intLen

 'take the left-most chr
 str1C = Left(strWork,1)
 'if it's numeric
 If IsNumeric(str1C) Then
  'concatenate the digit
  intNumber = intNumber + CInt(str1C)
  'remove 1st chr from the work variable
  strWork = Right(strWork,Len(strWork)-1)
 Else  'left-most chr isn't numeric
  FLN = intNumber  'output the leading number & exit
  Exit For
 End IF

Next  'work variable chr

End Function




'look for the App Path default value for an executable
Function AppPath (strFN)

Dim strKey, strValue, intErrNum

strKey = "Software\Microsoft\Windows\CurrentVersion\App Paths"

On Error Resume Next
 intErrNum = oReg.GetStringValue (HKLM,strKey & BS & strFN,"",strValue)
On Error GoTo 0

'return the value or an empty string (or garbage if value not set under W2K!)
If intErrNum = 0 And strValue <> "" Then
 AppPath = strValue
Else
 AppPath = ""
End If

End Function




'parse HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load
'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\run for executables
'and return co-name for each executable
'executables are delimited by spaces and/or commas
Function LRParse (strLine)

Dim i, strLRSeg  'counter, line segment
Dim strIn : strIn = Trim(strLine)  'input string
Dim intSLLI : intSLLI = Len(strIn)  'Input String Line Length
Dim strOut : strOut = ""  'output string
Dim arOut()  'dynamic executable output array
Dim cntAr : cntAr = -1  'output array UBound
Dim cntChr : cntChr = 0  'number of chrs in executable string
Dim intStartChr : intStartChr = 1  'start of executable string in input string

'for every chr in input string
For i = 1 To intSLLI

 'if the chr is a delimiter
 If Mid(strIn,i,1) = " " Or Mid(strIn,i,1) = "," Then

  'if at least one non-delimiter chr has been encountered
  If cntChr > 0 Then

   'extract the executable from the input string
   strLRSeg = Mid(strIn,intStartChr,cntChr)
   'if executable has no extension, add ".exe"

   If Fso.GetExtensionName(strLRSeg) = "" Then _
    strLRSeg = strLRSeg & ".exe"
   cntChr = 0  'reset the executable counter
   cntAr = cntAr + 1  'increment the output array UBound
   ReDim Preserve arOut(cntAr)  'redim the output array
   arOut(cntAr) = strLRseg  'add the executable to the output array

  End If  'non-delimiter chr encountered?

  intStartChr = i + 1  'reset the executable string start to next chr

 Else  'chr not a delimiter

  cntChr = cntChr + 1  'increment the exec string counter

 End If  'chr a delimiter?

Next  'line chr

'check the end-string
If cntChr > 0 Then

 'extract the executable
 strLRSeg = Mid(strIn,intStartChr,cntChr)
 cntAr = cntAr + 1  'increment the output array UBound
 ReDim Preserve arOut(cntAr)  'redim the output array
 arOut(cntAr) = strLRSeg  'add the executable to the output array

End If  'exec string found at end of line?

'if exec strings found
If cntAr >= 0 Then

 'for every string
 For i = 0 To UBound(arOut)

  If strOut = "" Then
   strOut = CoName(IDExe(arOut(i)))
  Else
   'concatenate a comma & co-name (with leading space)
   strOut = strOut & "," & CoName(IDExe(arOut(i)))
  End If

 Next

End If

'return delimited string
LRParse = strOut

End Function




'read JOB file & output error if file corrupt
Function JobFileRead (oFile, oJobFi)

'number of Unicode chrs in Run field executable statements,
'decimal value of enabled byte, command string, error number
Dim intUChrCtr, int1C, strCmd, intErrNum
Dim strJobExe : strJobExe = ""  'concatenated executable string
Dim flagEnStatus : flagEnStatus = False  'task enabled status

'check for minimum length
If oFile.Size <= 80 Then
 JobFileReadError oFile, " (too small)" : Exit Function
End If

On Error Resume Next

 'determine enabled/disabled status by reading one Unicode chr
 oJobFi.Skip(24)

 int1C = AscB(oJobFi.Read(1))

 'for a DISabled task: byte 48 (30h), 0-based-bit 2 (4-bit) = 1
 If (int1C And 4) = 0 Then flagEnStatus = True

 'if an enabled task
 If flagEnStatus Then

  'write titles & skip one line if not already done
  If strTitle <> "" Then
   TitleLineWrite : oFN.WriteBlankLines (1)
  End If

  'skip to the counter for the number of chrs in the first executable statement
  oJobFi.Skip(10)  'no of bytes at unicode chr 35 (byte 70)

  'no of chrs includes final zero chr so subtract one chr
  intUChrCtr = AscW(oJobFi.Read(1))-1

  'check for 0 or negative executable length
  If intUChrCtr <= 0 Then
   JobFileReadError oFile, " (no executable)"
   Exit Function
  End If

  'read the chrs and convert to ASCII
  strJobExe = MidB(oJobFi.Read(intUChrCtr),1)
  intErrNum = Err.Number : Err.Clear

  'check for truncated executable
  If intErrNum <> 0 Then
   JobFileReadError oFile, " (truncated executable)"
   Exit Function
  End If

  strCmd = strJobExe  'store executable for co-name ID
  'add ".exe" extension to bare executables
  If Fso.GetExtensionName(strCmd) = "" Then strCmd = strCmd & ".exe"

  'skip to parameters counter
  oJobFi.Skip(1)
  intErrNum = Err.Number : Err.Clear

  'check for truncated file
  If intErrNum <> 0 Then
   JobFileReadError oFile, " (too small)"
   Exit Function
  End If

  'read the parameters counter
  intUChrCtr = AscW(oJobFi.Read(1))
  intErrNum = Err.Number : Err.Clear

  'check for absence of parameters counter
  If intErrNum <> 0 Then
   JobFileReadError oFile, " (parameter string size missing)"
   Exit Function
  End If

  'if parameters exist, concatenate the executable
  If intUChrCtr <> 0 Then _
   strJobExe = strJobExe & Space(1) & MidB(oJobFi.Read(intUChrCtr-1),1)
  intErrNum = Err.Number : Err.Clear

  'check for truncated parameter string
  If intErrNum <> 0 Then
   JobFileReadError oFile, " (truncated parameter string)"
   Exit Function
  End If

  'write out the .JOB file name & executable string
  oFN.WriteLine Fso.GetBaseName(oFile.Path) &_
   " -> launches: " & strJobExe & CoName(IDExe(strCmd))

 End If  'enabled task?

On Error GoTo 0

End Function




'output reason for JOB file corruption
Function JobFileReadError (oFile, strReason)

 'write titles & skip one line if not already done
 If strTitle <> "" Then
  TitleLineWrite : oFN.WriteBlankLines (1)
 End If

 'write out the .JOB file name & error
 oFN.WriteLine Fso.GetBaseName(oFile.Path) &_
  " -> WARNING -- The file " & DQ & oFile.Name & DQ &_
  " is corrupt!" & strReason

End Function




'increment counters when IERESET.INF found-in-file-on-disk flag is False
Sub IERESETCounter (strSection, arIERSectionName, arSectionCount)

'if current INF section <> section for last not-found line
If strSection <> arIERSectionName Then  'if new section title

 'increment # sections, reset # lines in section
 'intSectionCount is an array index and initializes at -1
 'intSectionLineCount initializes at 0 for new section
 intSectionCount = intSectionCount + 1 : intSectionLineCount = 0

 '1st row = section name; 2nd row = # not-found lines in section
 'add column for new section to array, add title to array column
 ReDim Preserve arSectionCount(1,intSectionCount)
 arSectionCount(0,intSectionCount) = arIERSectionName
 'set current section = section for last-found line
 strSection = arIERSectionName

End If

'increment # lines not found in this section
intSectionLineCount = intSectionLineCount + 1

'increment # not-found lines in section
arSectionCount(1,intSectionCount) = intSectionLineCount

End Sub




'write title, sub-title, and sub-sub-title lines
Sub TitleLineWrite

Dim intTL  'Title Length

If strTitle <> "" Then  'output title line if necessary
 'do not underline " {++}" if present
 intTL = Len(strTitle)
 If InStr(strTitle, " {++}") > 0 Then intTL = intTL - 5
 oFN.WriteLine vbCRLF & vbCRLF & strTitle & vbCRLF &_
  String(intTL,"-")
 strTitle = ""
End If

If strSubTitle <> "" Then  'output sub-title line if necessary
 oFN.WriteLine vbCRLF & strSubTitle
 strSubTitle = ""
End If

If strSubSubTitle <> "" Then  'output sub-title line if necessary
 oFN.WriteLine vbCRLF & strSubSubTitle
 strSubSubTitle = ""
End If

End Sub




Sub CLSIDLocTitle (hLocHive, strKeyLoc, strCLSID, strLocTitle)

'assign default values
flagIsCLSID = False : strLocTitle = ""

'toggle flag if strCLSID in correct format
If IsCLSID(strCLSID) Then flagIsCLSID = True

'get title from value
'title retrieved successfully even if value of type REG_EXPAND_SZ
On Error Resume Next
 intErrNum = oReg.GetStringValue (hLocHive,strKeyLoc,strCLSID,strValue)
On Error GoTo 0

If intErrNum = 0 And strValue <> "" Then
 strLocTitle = strValue
Else
 strLocTitle = "(no title provided)"
End If  'strValue returned?

End Sub




'for CLSID name, recover CLSID title, CLSID\InProcServer32 DLL name, True: 32-bit in 64-bit OS
Sub ResolveCLSID (strCLSID, hCLSIDHive, strCLSIDTitle, strIPSDLL, flagWOW)

Dim strValue_1, strValue_2, strKey_1, strKey_2
Dim intErrNum_1, intErrNum_2, intErrNum_3
Dim arN, arT

'assign default values
strCLSIDTitle = "" : strIPSDLL = ""

strKey_1 = "Software\Classes\CLSID\" & strCLSID
strKey_2 = "Software\Classes\CLSID\" & strCLSID & "\InProcServer32"
If flagWOW Then
 strKey_1 = "Software\Classes\Wow6432Node\CLSID\" & strCLSID
 strKey_2 = "Software\Classes\Wow6432Node\CLSID\" & strCLSID & "\InProcServer32"
End If

'look for key
intErrNum_1 = oReg.EnumValues (hCLSIDHive,strKey_1,arN,arT)

'if key exists
If intErrNum_1 = 0 Then

 'look for title
 On Error Resume Next
  intErrNum_2 = oReg.GetStringValue (hCLSIDHive,strKey_1,"",strValue_1)
 On Error GoTo 0

 'set CLSID key title
 strCLSIDTitle = "(no title provided)"
 If intErrNum_2 = 0 And strValue_1 <> "" Then strCLSIDTitle = strValue_1

 'look for IPSDLL
 On Error Resume Next
  intErrNum_3 = oReg.GetExpandedStringValue (hCLSIDHive,strKey_2,"",strValue_2)
 On Error GoTo 0

 If intErrNum_3 = 0 And strValue_2 <> "" Then strIPSDLL = strValue_2

End If  'CLSID key exists?

End Sub




'search for CLSID verb at InProcServer32, LocalServer32, ProgID, VersionIndependentProgID subkeys
'
'two inputs: CLSID, upper limit of arCLSIDVerb to search
'five outputs: flag (TRUE if CLSID found to be a default value),
' string value of hive in which CLSID found,
' CLSID verb, default value of verb, CLSID title
Sub CLSIDPop (strCLSID, intLimit, flagAllowedVerb, strHive, strCLSIDVerb, strCLSIDVerbValue, strCLSIDTitle)

'initialize variables
strCLSIDVerbValue = "" : strCLSIDTitle = ""

'counters x 3, CLSID key, CLSID key + verb, error numbers x 2
Dim i, j, k, strCLSIDKey, strCLSIDSubKey, intErrNum, intErrNum1
'TRUE if CLSID resolved, used to back out of For loops
Dim flagFoundHere : flagFoundHere = False
Dim strCLSIDDefaultValue  'CLSID default value (used for title)

Dim arCLSIDVerbs : arCLSIDVerbs = Array("InProcServer32","LocalServer32", _
 "ProgID","VersionIndependentProgID")

'look for CLSID verbs up to limit
For i = 0 To intLimit

 'exit if subverb action already found
 If flagFoundHere Then Exit For

 'look in each hive
 For j = 0 To 1

  'exit if subverb action already found
  If flagFoundHere Then Exit For

  'form CLSID key & CLSID verb key
  strCLSIDKey = "SOFTWARE\Classes\CLSID\" & strCLSID
  strCLSIDSubKey = strCLSIDKey & BS & arCLSIDVerbs(i)

  'retrieve CLSID verb key default value
  On Error Resume Next
   intErrNum = oReg.GetStringValue (arHives(j,1),strCLSIDSubKey,"",strCLSIDVerbValue)
  On Error GoTo 0

  'if CLSID verb default value found
  If intErrNum = 0 And strCLSIDVerbValue <> "" Then

   flagFoundHere = True

   strHive = arHives(j,0) : strCLSIDVerb = arCLSIDVerbs(i)

   'look for CLSID title
   On Error Resume Next
    intErrNum1 = oReg.GetStringValue (arHives(j,1),strCLSIDKey,"",strCLSIDDefaultValue)
   On Error GoTo 0

   'set CLSID key title
   strCLSIDTitle = "(no title provided)"
   If intErrNum1 = 0 And strCLSIDDefaultValue <> "" Then _
    strCLSIDTitle = strCLSIDDefaultValue

   'check if CLSID verb is default
   For k = 0 To UBound(arAllowedHandlerGrammar)

    If LCase(Trim(strCLSIDVerbValue)) = LCase(arAllowedHandlerGrammar(k)) Then
     flagAllowedVerb = True : Exit For  'if default, toggle flag and exit
    End If

   Next  'arAllowedHandlerGrammar member

  End If  'CLSID verb default value found?

 Next  'j hive

Next  'i arCLSIDVerbs

End Sub




'find directories with System attribute and DESKTOP.INI file
'with .ShellClassInfo section and CLSID statement
Sub DirSysAtt (oDir)

'sub-dir collection & count, single sub-dir, error number
Dim colSF, cntSF, oSF, intErrNum
'DeskTop.Ini path string & Parse return string,
Dim strDTI, strDTIP

'avoid "RECYCLER" And "System Volume Information" directories
If InStr(LCase(oDir),"recycler") > 0 Or _
 InStr(LCase(oDir),"recycled") > 0 Or _
 InStr(LCase(oDir),"system volume information") > 0 Then Exit Sub

'increment folder count
ctrFo = ctrFo + 1

'form DESKTOP.INI path string
strDTI = oDir.Path & "\DESKTOP.INI"
'if root directory, backslash is present by default
If oDir.IsRootFolder Then strDTI = oDir.Path & "DESKTOP.INI"

'if System attribute present And DESKTOP.INI CLSID exists,
'add path to array & increment count
If (oDir.Attributes And 4) And Fso.FileExists(strDTI) Then
 strDTIP = DTIParse(strDTI)
 If strDTIP <> "" Then
  ReDim Preserve arSDDTI(ctrArDTI) : arSDDTI(ctrArDTI) = strDTIP
  ctrArDTI = ctrArDTI + 1
 End If  'return string not empty?
End If  'S And DTI exists?

'count the sub-folders, trap any error (prob. due to permissions)
On Error Resume Next
 Set colSF = oDir.SubFolders : cntSF = colSF.Count
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if no error, recurse the sub-folders
If intErrNum = 0 Then
 For Each oSF In colSF : DirSysAtt oSF : Next
 Set colSF=Nothing
Else  'add (permissions) error to array & increment count
 ReDim Preserve arSDErr(ctrArErr) : arSDErr(ctrArErr) = oDir.Path
 ctrArErr = ctrArErr + 1
End If

End Sub




'return output string for DESKTOP.INI with CLSID statement
'consisting of CLSID and InProcServer32 DLL
Function DTIParse (strDTIFN)

'DESKTOP.INI file, error number, CoName
Dim oDTIFi, intErrNum, strIPSDLL, strCN
Dim strOut : strOut = ""  'output string
'file line, Lower-Case Left-Trimmed line, pos'n of equals sign
'CLSID, This Sub keys array/string, This Sub CLSID Title Hive Location, counters x 2
Dim strLine, strLCLT, intEq, strCLSID, arTSKeys, strTSKey, strTSCTHL, intTSKey, i
Dim flagSection : flagSection = False  'in [.ShellClassInfo]?
Dim flagAllow  'IPS DLL on allowed list?
Dim flagTitle  'hive title line written?

DTIParse = ""  'by default, return empty string

'try to open DESKTOP.INI
On Error Resume Next
 Set oDTIFi = Fso.OpenTextFile(strDTIFN,1,False,0)
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'return error if file can't be opened
If intErrNum <> 0 Then
 DTIParse = strDTIFN & " -- cannot be opened!" : Exit Function
End If

'[.shellclassinfo]
'CLSID=
'UICLSID=

'for every line
Do While Not oDTIFi.AtEndOfStream

 strLine = oDTIFi.ReadLine
 strLCLT = LCase(LTrim(strLine))

 'detect [.ShellClassInfo]
 If Left(strLCLT,1) = "[" And InStr(strLCLT,".shellclassinfo") > 0 Then

  flagSection = True

 'toggle flag if encountered another section before CLSID statement
 ElseIf Left(strLCLT,1) = "[" And InStr(strLCLT,".shellclassinfo") = 0 Then

  flagSection = False

 'detect "CLSID=" or "UICLSID="
 ElseIf flagSection And (Left(strLCLT,5) = "clsid" Or _
  Left(strLCLT,7) = "uiclsid") Then

  'find "="
  intEq = InStr(1,strLCLT,"=",1)

  'if "=" past "CLSID"
  If intEq > 5 Then

   strCLSID = RTrim(Mid(strLCLT,intEq + 1))  'save the string past the equals

   arTSKeys = Array("Software\Classes\CLSID\" & strCLSID & "\InProcServer32")

   If intBits = 64 Then

    arTSKeys = Array("Software\Classes\CLSID\" & strCLSID & "\InProcServer32", _
     "Software\Classes\Wow6432Node\CLSID\" & strCLSID & "\InProcServer32")

   End If

   flagTitle = False

   'for each arTSKeys member
   For intTSKey = 0 To UBound(arTSKeys)

    'assign CLSID location output string
    strTSCTHL = LIP & "CLSID}\"
    If InStr(UCase(arTSKeys(intTSKey)),"WOW") > 0 Then _
     strTSCTHL = LIP & "Wow" & LIP & "CLSID}\"

    'for each hive
    For ctrCH = intCLL To 1

     'get the CLSID IPS from the registry
     On Error Resume Next
      intErrNum = oReg.GetExpandedStringValue (arHives(ctrCH,1),arTSKeys(intTSKey),"", strIPSDLL)
     On Error GoTo 0

     'if the IPS DLL exists, check if it's allowed, CoName = MS & CLSID hive = HKLM
     If intErrNum = 0 And strIPSDLL <> "" Then

      flagAllow = False : strCN = CoName(IDExe(strIPSDLL))

      For i = 0 To UBound(arOKDLLs)
       If LCase(Fso.GetFileName(strIPSDLL)) = LCase(arOKDLLs(i)) And _
        strCN = MS And ctrCH = 1 Then
         flagAllow = True : Exit For
       End If  'allowed?
      Next  'allowed IPS DLL

      'form string if DLL not allowed Or ShowAll
      If Not flagAllow Or flagShowAll Then

       If strOut = "" Then  'if no output yet, write full headers

        strOut = vbCRLF & strDTIFN & vbCRLF & "[.ShellClassInfo]" &_
         vbCRLF & strLine & vbCRLF & "  -> {" & arHives(ctrCH,0) & strTSCTHL &_
        "InProcServer32\(Default) = " & strIPSDLL & strCN
        flagTitle = True

       Else  'concatenate add'l text

        If Not flagTitle Then  'no output for this line, so write line

         strOut = strOut & vbCRLF & strLine & vbCRLF & "  -> {" &_
          arHives(ctrCH,0) & strTSCTHL & "InProcServer32\(Default) = " &_
          strIPSDLL & strCN

         flagTitle = True

        Else  'flagTitle True - current file line has generated output,
              'so just append CLSID info

         strOut = strOut & vbCRLF & "  -> {" & arHives(ctrCH,0) &_
          strTSCTHL & "InProcServer32\(Default) = " & strIPSDLL & strCN

        End If  'flagTitle?

       End If  'strOut empty?

      End If  'DLL not allowed?

     End If  'IPS DLL exists?

    Next  'CLSID hive

   Next  'arTSKeys

  End If  'equals sign past "CLSID" or "UICLSID"?

 End If  'in [.ShellClassInfo] section?

Loop  'DESKTOP.INI line

oDTIFi.Close : Set oDTIFi=Nothing

'set function value & exit
DTIParse = strOut

End Function




'CLasses Analysis sub -- finds default value and SxC default values
'(for Wn8, also DelegateExecute default value), enumerates SxDDEexe subkeys
'.ext index, hive index, classes branch key + progid, returned progid array
Sub CLAnal (i, k, strCLKey, arKDV())

'Key Default Value (DV), Shell DV, Shell\x\Command DV, ddeexec DV
Dim strKDV, strSDV, strSxCDV, strDDEDV
Dim strCVDV  'CurVer DV
Dim strOutTmp : strOutTmp = ""  'output string
Dim arSSK, strSSK  'Shell Sub-Keys array/key
Dim arSxCDV(), arShellVal  'SxC key, SxC DV (2 row x n col) array / shell value array
Dim intUL, j, jj  'counters

'if arKDV not yet populated, set UBound to 0 (for 1st member)
On Error Resume Next
 'try to get the UBound
 Dim intCntDV : intCntDV = UBound(arKDV)
 intErrNum = Err.Number
On Error Goto 0

'if no members present, UBound throws error
If intErrNum <> 0 Then
 'dim the array for a single member and fill it with an MT string
 intCntDV = 0 : ReDim arKDV(0) : arKDV(0) = ""
Else  'intErrNum = 0, array exists so increment counter for next ReDim
 intCntDV = intCntDV + 1
End If

Dim flagSxCDV : flagSxCDV = False  'True when S\x\C DV found

'skip HKLM\SOFTWARE\Wow6432Node\Classes
'(symbolically linked to HKLM\SOFTWARE\Classes\Wow6432Node)
If Not (intBits = 64 And arHives(k,0) = "HKLM" And _
 InStr(LCase(strCLKey),"software\wow6432node\classes") > 0) Then

 'check that the input key exists
 intErrNum0 = oReg.EnumValues(arHives(k,1),strCLKey,arShellVal)

 If intErrNum0 = 0 Then

  'look for non MT default value (progid or progid-id)
  intErrNum = oReg.GetStringValue (arHives(k,1),strCLKey,"",strKDV)

  If intErrNum = 0 And strKDV <> "" Then

    'add DV to arKDV

    ReDim Preserve arKDV (intCntDV)
    arKDV(intCntDV) = strKDV : intCntDV = intCntDV + 1

    'strKDV is either filetype for an extension or arbitrary text for a filetype
    'if the former and not default, append to output string now
    'if the latter, there is no default (may be language-dependent),
    'so store for output if filetype SOC not default

   'prepare output string if (ShowAll Or not HKLM Or DV <> default filetype for extension)
   If flagShowAll Or arHives(k,0) <> "HKLM" Or LCase(strKDV) <> LCase(arExeFT(i)) Then

    'append to output string now if not default filetype for extension
    If (LCase(strCLKey) = "software\classes\" & LCase(arExeExt(i))) Or _
      (LCase(strCLKey) = "software\wow6432node\classes\" & LCase(arExeExt(i))) Or _
      (LCase(strCLKey) = "software\classes\wow6432node\" & LCase(arExeExt(i))) Then
     strOut = StrOutSep(strOut, SOCA(arHives(k,0) & BS & strCLKey) &_
      "\(Default) = " & strKDV, vbCRLF)
    Else  'for filetype DV (which has no default), prepare string to append to
          'output string later if SOC not default
     strOutTmp = SOCA(arHives(k,0) & BS & strCLKey) & "\(Default) = " & strKDV
    End If

   End If  'output needed?

  Else  'progid DV not found

   'if HKLM And Classes\...\.ext (for progid, default value unimportant)
   If arHives(k,0) = "HKLM" And (LCase(strCLKey) = "software\classes\" & LCase(arExeExt(i)) Or _
    LCase(strCLKey) = "software\classes\wow6432node\" & LCase(arExeExt(i))) Then

    'output that progid value not set
    strOut = StrOutSep(strOut,SOCA(arHives(k,0) & BS & strCLKey) &_
     "\(Default) = (value not set)",vbCRLF)

   End If  'HKLM And .ext?

  End If  'progid key exists?


  'look for Shell key via EnumValues
  intErrNum1 = oReg.EnumValues (arHives(k,1),strCLKey & "\shell",arShellVal)

  If intErrNum1 = 0 Then  'shell key exists

   intErrNum2 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell", "",strSDV)

   If intErrNum2 = 0 And strSDV <> "" Then  'shell DV not MT

    'output if shell DV <> open
    If LCase(strSDV) <> "open" Then

     'since this is not default, append progid DV to output
     strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

     strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
      strCLKey) & "\shell\(Default) = " & strSDV, vbCRLF)

    End If  'shell DV<>open?

    'look for SxC DV
    intErrNum3 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\" &_
     strSDV & "\command", "",strSxCDV)

    If intErrNum3 = 0 And strSxCDV <> "" Then  'if SxC DV found

     flagSxCDV = True  'toggle flag

     'since this is not default, append progid DV to output
     strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

     'output SxC DV + CoName
     strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
      strCLKey) & "\shell\" & strSDV & "\command\(Default) = " &_
      strSxCDV & CoName(IDExe(strSxCDV)),vbCRLF)

     'check for ddeexec key and enumerate if present
     intErrNum4 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\" &_
      strSDV & "\ddeexec","",strDDEDV)

     'if ddeexec key exists with non MT default value, enumerate the key
     If intErrNum4 = 0 And strSDV <> "" Then _
      DDEX k, strCLKey & "\shell\" & strSDV & "\ddeexec"

    ElseIf strOSSS = "WN8" Then  'under Wn8, look for DelegateExecute value if DV MT

     intErrNum5 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\" &_
      strSDV & "\command","DelegateExecute",strSxCDV)

     If intErrNum5 = 0 And strSxCDV <> "" Then

      flagSxCDV = True

      'since this is not default, append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

      'output DelegateExecute DV
      strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
       strCLKey) & "\shell\" & strSDV & "\command\DelegateExecute = " & strSxCDV,vbCRLF)

      'resolve the CLSID
      If IsCLSID(strSxCDV) Then CLSID_ID strSxCDV, False

     End If  'DelegateExecute not MT?

    End If  'SxC DV not MT?

   Else  'Shell DV MT

    'look for SOC DV
    intErrNum6 = oReg.GetStringValue (arHives(k,1),strCLKey &_
     "\shell\open\command", "",strSxCDV)

    'if SOC DV exists and not MT
    If intErrNum6 = 0 And strSxCDV <> "" Then

     flagSxCDV = True  'toggle flag

     'prepare output if (not ShowAll Or not HKLM Or not default)
     If flagShowAll Or arHives(k,0) <> "HKLM" Or LCase(strSxCDV) <> LCase(arExpVal(i)) Then

      'since output is required, append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

      'if default, add to output w/o CoName
      If LCase(strSxCDV) = LCase(arExpVal(i)) Then
       strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
        strCLKey) & "\shell\open\command\(Default) = " & strSxCDV,vbCRLF)
      Else  'non default, so add to output with CoName
       strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
        strCLKey) & "\shell\open\command\(Default) = " & strSxCDV & CoName(IDExe(strSxCDV)),vbCRLF)
      End If

     End If  'output required?

     'check for ddeexec key and enumerate if present
     intErrNum7 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\open\ddeexec","",strSDV)

     If intErrNum7 = 0 And strSDV <> "" Then
      DDEX k, strCLKey & "\shell\open\ddeexec"
     End If

    ElseIf strOSSS = "WN8" Then  'under Wn8, look for DelegateExecute value if DV MT

     intErrNum8 = oReg.GetStringValue (arHives(k,1),strCLKey &_
      "\shell\open\command","DelegateExecute",strSxCDV)

     'if DelegateExecute value not MT
     If intErrNum8 = 0 And strSxCDV <> "" Then

      flagSxCDV = True

      'append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

      'output DelegatExecute DV
      strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
       strCLKey) & "\shell\open\command\DelegateExecute = " & strSxCDV,vbCRLF)

      'resolve the CLSID
      If IsCLSID(strSxCDV) Then CLSID_ID strSxCDV, False

     End If  'DelegateExecute not MT?

    End If  'SOC DV not MT?

   End If  'SDV not MT?


   If Not flagSxCDV Then  'if SxC DV value not found

    'enumerate shell sub-keys
    intErrNum9 = oReg.EnumKey(arHives(k,1),strCLKey & "\shell",arSSK)

    'if sub-keys found
    If intErrNum9 = 0 And IsArray(arSSK) Then

     'count them
     intUL = UBound(arSSK)

     'warn if > 100 subkeys
     If intUL > 99 Then

      'since output is required, append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

      'output warning about large number of subkeys
      strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
       strCLKey) & "\shell\ has " & intUL + 1 & " subkeys -- corruption is likely",vbCRLF)

     End If  '>100 subkeys found?

     j = 0  'initialize SxC DV counter

     'for each Shell subkey
     For Each strSSK In arSSK

      intErrNum10 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\" &_
       strSSK & "\command", "",strSxCDV)

      'if SxC DV exists
      If intErrNum10 = 0 And strSxCDV <> "" Then

       'if 0-based SxC DV count > 24
       If j > 24 Then

        'since output is required, append progid DV to output
        strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

        'output warning about large number of SOC entries
        strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
         strCLKey) & "\shell\ has at least 25 subkeys with [verb]\command values -- corruption is likely",vbCRLF)

        Exit For

       ElseIf strOSSS = "WN8" Then  'under Wn8, look for DelegateExecute value if DV MT

        intErrNum11 = oReg.GetStringValue (arHives(k,1),strCLKey & "\shell\" &_
         strSSK & "\command","DelegateExecute",strSxCDV)

        If intErrNum11 = 0 And strSxCDV <> "" Then

         flagSxCDV = True

         'since output is required, append progid DV to output
         strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

         'output DelegatExecute DV
         strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
          strCLKey) & "\shell\" & strSSK & "\command\DelegateExecute = " & strSxCDV,vbCRLF)

         'resolve the CLSID
         If IsCLSID(strSxCDV) Then CLSID_ID strSxCDV, False

        End If  'DelegateExecute not MT?

       End If  '> 24 SxC DV?

       'save SxC DV in array
       'ReDim of multi-dimensional array can _only_ operate on _last_ index
       ReDim Preserve arSxCDV(1,j)
       arSxCDV(0,j) = strCLKey & "\shell\" & strSSK & "\command" : arSxCDV(1,j) = strSxCDV
       j = j + 1

      Else  'strSxCDV MT so try to find ddeexec under Sx_

       DDEX k, strCLKey & "\shell\" & strSSK & "\ddeexec"

      End If  'strSxCDV not MT?

     Next  'arSSK member

     'btwn 5-25 SxC DVs
     If j > 4 And j < 26 Then

      'since output is required, append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

      'output warning about excessive SOC entries
      strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS &_
       strCLKey) & "\shell\ has more than 5 subkeys with [verb]\command values -- only 5 will be shown",vbCRLF)

     End If  '5-25 SxC DV's?

      'since j is incremented _before_ it's used as an index,
      'if j=0, arSxCDV is null so avoid this section
      If j > 0 Then

      'output max 5 SxC DV's
      intUL = UBound(arSxCDV,2) : If intUL > 4 Then intUL = 4

      'since output is required, append progid DV to output
      strOut = StrOutSep (strOut, strOutTmp, vbCRLF)

      For jj = 0 To intUL

       'output SxC DV + CoName
       strOut = StrOutSep (strOut, SOCA(arHives(k,0) & BS & arSxCDV(0,jj)) & "\(Default) = " &_
         arSxCDV(1,jj) & CoName(IDExe(arSxCDV(1,jj))),vbCRLF)

       'check for ddeexec key and enumerate if present
       intErrNum12 = oReg.GetStringValue (arHives(k,1),strCLKey & BS & strSDV & "\ddeexec","",strSDV)

       If intErrNum12 = 0 And strSDV <> "" Then
        DDEX k, strCLKey & BS & strSDV & "\ddeexec"
       End If

      Next  'SxC DV

     End If  'j>0?

    End If  'shell SK's found

   End If  'flagSxCDV?

  End If  'shell key exists?

  'for all branch locations, look for CurVer subkey DV
  intErrNum13 = oReg.GetStringValue (arHives(k,1),strCLKey & BS & "CurVer","",strCVDV)

  If intErrNum13 = 0 And strCVDV <> "" Then

   'since output is required, append progid DV to output
   strOut = StrOutSep (strOut, strOutTmp, vbCRLF) : strOutTmp = ""

   'output CurVer DV
   strOut = StrOutSep(strOut,SOCA(arHives(k,0) & BS &_
    strCLKey & BS & "CurVer") & "\(Default) = " & strCVDV,vbCRLF)

  End If  'shell key exists?

 Else  'input key doesn't exist

  'if HKLM And .ext Or filetype
  If arHives(k,0) = "HKLM" And (LCase(strCLKey) = "software\classes\" & LCase(arExeExt(i)) Or _
   LCase(strCLKey) = "software\classes\" & LCase(arExeFT(i)) Or _
   LCase(strCLKey) = "software\classes\wow6432node" & LCase(arExeExt(i)) Or _
   LCase(strCLKey) = "software\classes\wow6432node" & LCase(arExeFT(i))) Then

   'output that key not found
   strOut = StrOutSep(strOut,SOCA(arHives(k,0) & BS & strCLKey) & " = (key not found)",vbCRLF)

  End If  'output required?

 End If  'input key exists?

End If  'not symbolically-linked Wow6432Node branch?

End Sub




Sub SortArray (arIn())

Dim i, j  'indexes
Dim strTemp

'reorder the array alphabetically
For i = 0 To (UBound(arIn) - 1)

 For j = i to 0 Step -1

  If UCase(arIn(j+1)) < UCase(arIn(j)) Then

   strTemp = arIn(j)
   arIn(j) = arIn(j+1)
   arIn(j+1) = strTemp

  End If  'UCase identical?

 Next  'j

Next  'i

End Sub




Sub UnDupeArray (arIn())

Dim i, j  'indexes
Dim strTemp

'remove duplicate entries
For i = 0 To (UBound(arIn) - 1)

 If arIn(i) <> "" Then

  For j = i to UBound(arIn) - 1

   If UCase(arIn(j+1)) = UCase(arIn(i)) Then

    arIn(j+1) = ""

   End If  'UCase identical?

  Next  'j

 End If  'arIn(i) MT?

Next  'i

End Sub




'for CLSID name, recover CLSID title, CLSID\InProcServer32 DLL name
'GUID, write to file (T) or save to strOut (F)
Sub CLSID_ID (strCLSID, flagWrite)

'keys where CLSIDs are found, counters x 2
Dim arKeys, i, intHive, strCLSIDTitle, strIPSDLL
Dim strValue_1, strValue_2, strIPSDLLKey
Dim intErrNum_1, intErrNum_2, intErrNum_3
Dim arN, arT  'value name/type arrays

arKeys = Array("Software\Classes\CLSID\" & strCLSID)
If intBits = 64 Then
 arKeys = Array("Software\Classes\CLSID\" & strCLSID, _
  "Software\Wow6432Node\Classes\CLSID\" & strCLSID, _
  "Software\Classes\Wow6432Node\CLSID\" & strCLSID)
End If

For i = 0 To UBound(arKeys)

 ReDim Preserve arIPSDLL(i)

 For intHive = intCLL To 1

  'avoid symbolically linked HKLM Wow6432node key
  If Not (intBits = 64 And arHives(intHive,0) = "HKLM" And _
   InStr(LCase(arKeys(i)),"software\wow6432node\classes") > 0) Then

   intErrNum_1 = oReg.EnumValues (arHives(intHive,1),arKeys(i),arN,arT)

   'if key exists
   If intErrNum_1 = 0 Then

    'look for title
    On Error Resume Next
     intErrNum_2 = oReg.GetStringValue (arHives(intHive,1),arKeys(i),"",strCLSIDTitle)
    On Error GoTo 0

    'set CLSID key title
    If strCLSIDTitle = "" Then strCLSIDTitle = "(no title provided)"

    'look for IPSDLL
    strIPSDLLKey = arKeys(i) & "\InprocServer32"
    On Error Resume Next
     intErrNum_3 = oReg.GetExpandedStringValue (arHives(intHive,1),strIPSDLLKey,"",strIPSDLL)
    On Error GoTo 0

    If strIPSDLL = "" Then strIPSDLL = "(value not set)"

    arIPSDLL(i) = strIPSDLL

    'output CLSID title, IPSDLL & CoName

    strCTHL = LIP & "CLSID} = " : intCTHLS = intCS
    If InStr(LCase(strIPSDLLKey),"wow6432node") > 0 Then
     strCTHL = LIP & "Wow" & LIP & "CLSID} = " : intCTHLS = intCWS
    End If

    If flagWrite then

     oFN.WriteLine "  -> {" & arHives(intHive,0) & strCTHL &_
      strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
      strIPSDLL & CoName(IDExe(strIPSDLL))

    Else

     strOut = StrOutSep(strOut,"  -> {" & arHives(intHive,0) & strCTHL &_
      strCLSIDTitle & vbCRLF & Space(intCTHLS) & "\InProcServer32\(Default) = " &_
      strIPSDLL & CoName(IDExe(strIPSDLL)),vbCRLF)

    End If  'flagWrite?

   End If  'CLSID key exists?

  End If  'symbolically-linked Wow6432Node key?

 Next  'hive

Next  'key

End Sub




'look for shell\open\ddeexec default values
Sub DDEX (intHive, strKey)

'error x 3, returned value, arrays of key values/value types
Dim intErrNum, intErrNum1, intErrNum2, strDDDV, arNames, arType
Dim arSubKeys, strSubKey, strSKDV

'look for ddeexec key
intErrNum = oReg.EnumValues (arHives(intHive,1),strKey,"",arNames,arType)

'if ddeexec key exists
If intErrNum = 0 Then

 'get default value
  intErrNum1 = oReg.GetStringValue (arHives(intHive,1),strKey,"",strDDDV)

 strOut = StrOutSep (strOut, SOCA(arHives(intHive,0) & BS &_
  strKey) & "\(Default) = " & strDDDV,vbCRLF)

 'find all the subkeys
 oReg.EnumKey arHives(intHive,1), strKey, arSubKeys

 'enumerate data if present
 If IsArray(arSubKeys) Then

  'for each ddeexec subkey
  For Each strSubKey In arSubKeys

   'get default value
   intErrNum2 = oReg.GetStringValue(arHives(intHive,1),strKey & BS & strSubKey,"",strSKDV)

   'if default value exists and not MT
   If intErrNum2 = 0 And strSKDV <> "" Then

    strOut = StrOutSep (strOut, SOCA(arHives(intHive,0) & BS &_
     strKey & BS & strSubKey) & "\(Default) = " & strSKDV, vbCRLF)

   End If  'ddeexec subkey default value exists?

  Next  'ddeexec subkey

 End If  'ddeexec subkey array exists?

End If  'ddeexec key exists?

End Sub




'initial output string, string to add, Separator string
Function StrOutSep (strOut, strAdd, strSep)

'if output string and string to add not empty, separate added string with strSep
If strOut <> "" And strAdd <> "" Then
 StrOutSep = strOut & strSep & strAdd
ElseIf strAdd <> "" Then  'initial string empty, set output to added string
 StrOutSep = strAdd
ElseIf strOut <> "" Then  'added string empty, set output to initial string
 StrOutSep = strOut
Else  'both empty
 StrOutSep = ""
End If

End Function




'recurse sub-directories for WVa/Wn7 Scheduled Tasks, run ESTParse sub on contents
Sub DirEST (oDir)

Dim strOutFo : strOutFo = ""  'output string for the folder

'File/Sub-Folder collections & count, single file/sub-dir
Dim colFi, colSF, oFi, oSF

'avoid "RECYCLER" And "System Volume Information" directories
If InStr(LCase(oDir.Name),"recycler") > 0 Or _
 InStr(LCase(oDir.Name),"recycled") > 0 Or _
 InStr(LCase(oDir.Name),"system volume information") > 0 Then Exit Sub

Set colFi = oDir.Files  'get the file collection

'trap any file access errors in the directory
'parse each file for EST info and append info to output string
On Error Resume Next

 For Each oFi In colFi

  strTmp = ESTParse(oFi.Path)
  If strTmp <> "" Then  'if EST found

   If strOutFo <> "" Then  'if output string not MT
    strOutFo = strOutFo & vbCRLF & strTmp  'add EST to next line
   Else  'output string still MT
    strOutFo = strTmp  'don't precede EST string with CR
   End If  'output string MT?

  End If  'EST found?

 Next  'next file in directory
 intErrNum = Err.Number : Err.Clear

On Error GoTo 0

'in case of access error, save the directory path in the error array
' increment the error count & exit
If intErrNum <> 0 Then
 ReDim Preserve arErr(ctrErr) : arErr(ctrErr) = oDir.Path
 ctrErr = ctrErr + 1 : Exit Sub
End If

'if EST's found, prefix the output string with the directory path
If strOutFo <> "" Then
 If strOut = "" Then  'if first directory with output
  'place EST's below directory path
  strOut = oDir.Path & vbCRLF & strOutFo
 Else  'not first directory with output
  'put blank line between old and new strings, then follow with
  'directory path and new EST's
  strOut = strOut & vbCRLF & vbCRLF & oDir.Path & vbCRLF & strOutFo
 End If  'first directory with output?
End If  'EST's found in directory?

'get the sub-folder collection, trap any error (prob. due to permissions)
On Error Resume Next
 Set colSF = oDir.SubFolders
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if no error, recurse the sub-folders
If intErrNum = 0 Then
 For Each oSF In colSF : DirEST oSF : Next
 Set colSF=Nothing
Else  'add (permissions) error to array & increment count
 ReDim Preserve arErr(ctrErr) : arErr(ctrErr) = oDir.Path
 ctrErr = ctrErr + 1
End If

End Sub




'WVa/Wn7 Enabled Scheduled Task (XML file) Parser
'entire sub is inside "On Error Resume Next" via
'calling sub DirEST
Function ESTParse (strESTFN)

Dim strCLSID, strCLSIDTitle, strIPSDLL, strNodeText
'key array, key array index, output string, output spacing
Dim arTSKeys, intTSKey, strTSCTHL, intTSCTHLS
Dim strArg, flagIPSFnd
Dim flagDisabled : flagDisabled = False  'disabled flag

Dim strHidden : strHidden = ""

ESTParse = ""  'by default, return empty string

'create XML document
Dim oXMLFi: Set oXMLFi = CreateObject("MSXML2.DOMDocument")

'try to open argument (task file)
On Error Resume Next
 oXMLFi.Load strESTFN
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'exit if file can't be opened
If intErrNum <> 0 Then Exit Function

'exit if not a valid XML file or if file cannot be opened due to
'insufficient permissions
'also available: oXMLFi.ParseError.ErrorCode, oXMLFi.ParseError.Reason
If oXMLFi.ParseError.ErrorCode <> 0 Then Exit Function

On Error Resume Next
 strNodeText = LCase(oXMLFi.SelectSingleNode("//Settings/Enabled").text)
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

If intErrNum = 0 Then
 If strNodeText = "false" Then flagDisabled = True
End If

'if task is not disabled
If Not flagDisabled Then

 'check if hidden
 '*MUST* enclose within On Error, set .text property, save error number,
 'test error number subsequently and *then* set dependent variable value
 On Error Resume Next
  strNodeText = LCase(oXMLFi.SelectSingleNode("//Settings/Hidden").text)
  intErrNum = Err.Number : Err.Clear
 On Error GoTo 0

 If intErrNum = 0 Then
  If strNodeText = "true" Then strHidden = "(HIDDEN!)"
 End If

 'look for Custom Handler
 'removal of "On Error Resume Next" generated error if CLSID not
 ' present and caused Function to return, but script did not abort
 On Error Resume Next
  strCLSID = oXMLFi.SelectSingleNode("//ComHandler/ClassId").text
  intErrNum = Err.Number : Err.Clear
 On Error GoTo 0

 If intErrNum = 0 Then  'Custom Handler present

  'add CLSID to output string
  ESTParse = Fso.GetFileName(strESTFN) &_
   " -> " & strHidden & " launches: " & strCLSID

  flagIPSFnd = False  'assume IPS DLL doesn't exist

  arTSKeys = Array("Software\Classes\CLSID\" & strCLSID & "\InProcServer32")

  If intBits = 64 Then

   arTSKeys = Array("Software\Classes\CLSID\" & strCLSID & "\InProcServer32", _
    "Software\Classes\Wow6432Node\CLSID\" & strCLSID & "\InProcServer32")

  End If

  'if braces omitted, try adding them
  If Not IsCLSID(strCLSID) Then strCLSID = "{" & strCLSID & "}"

  'for each arTSKeys member
  For intTSKey = 0 To UBound(arTSKeys)

   'look for InProcServer32 in HKCU/HKLM Classes/ & Classes\Wow6432Node
   For ctrCH = 0 To 1

    flagWOW = False
    If InStr(UCase(arTSKeys(intTSKey)),"WOW") > 0 Then flagWOW = True
    ResolveCLSID strCLSID, arHives(ctrCH,1), strCLSIDTitle, strIPSDLL, flagWOW

    'if IPS found
    If strIPSDLL <> "" Then

     flagIPSFnd = True  'toggle flag

     strTSCTHL = LIP & "CLSID} = " : intTSCTHLS = intCS
     If flagWOW Then
      strTSCTHL = LIP & "Wow" & LIP & "CLSID} = " : intTSCTHLS = intCWS
     End If

     'append IPS string to output string
     ESTParse = ESTParse & vbCRLF &_
      "  -> {" & arHives(ctrCH,0) & strTSCTHL &_
      strCLSIDTitle & vbCRLF & Space(intTSCTHLS) & "\InProcServer32\(Default) = " &_
      strIPSDLL & CoName(IDExe(strIPSDLL))

    End If  'strIPSDLL exists?

   Next  'CLSID hive

  Next  'arTSKeys member

  'if IPS not found, say it and return
  If Not flagIPSFnd Then ESTParse = ESTParse &_
   " [InProcServer32 entry not found]"

 End If  'Custom Handler present?

 'look for executable command
 'removal of "On Error Resume Next" generated error if CLSID not
 ' present and caused Function to return, but script did not abort
 On Error Resume Next
  strCmd = oXMLFi.SelectSingleNode("//Command").text
  intErrNum = Err.Number : Err.Clear
 On Error GoTo 0

 'if command exists, save to output
 If intErrNum = 0 Then
  ESTParse = Fso.GetFileName(strESTFN) &_
   " -> " & strHidden & " launches: " & strCmd

  strCN = CoName(IDExe(strCmd))  'find CoName

  'look for executable arguments
  'removal of "On Error Resume Next" generated error if CLSID not
  ' present and caused Function to return, but script did not abort
  On Error Resume Next
   strArg = oXMLFi.SelectSingleNode("//Arguments").text
   intErrNum1 = Err.Number : Err.Clear
  On Error GoTo 0

  'if arguments exist, add to output and return
  If intErrNum1 = 0 Then
   ESTParse = ESTParse & Space(1) & strArg & strCN
  ElseIf ESTParse <> "" Then  'otherwise terminate output string
   ESTParse = ESTParse & strCN
  End If

 End If  'command exists?

End If  'task not disabled?

End Function




'hex hive, registry key
Sub GPRecognizer (hHive, strKey)

'error number, counters x 2, Known Setting Index,
'Group Policy setting location string, value type
Dim intErrNum, i, j, intKSI, intISI, strGPLoc, strType
Dim flagIgnore
Dim arNames, arType  'returned array of value names/types

Const UCFG = "{User Configuration|"
Const CCFG = "{Computer Configuration|"

strSubSubTitle = "HKCU\" & strKey & BS
If hHive = HKLM Then strSubSubTitle = SOCA("HKLM\" & strKey & BS)

'set up GPO type
Dim strGPOT : strGPOT = UCFG  'GPO Type
If hHive = HKLM Then strGPOT = CCFG

'obtain arrays of value names & types
intErrNum = oReg.EnumValues (hHive, strKey, arNames, arType)

'if array returned
If intErrNum = 0 And IsArray(arNames) Then

 'for every member of the names array
 For i = 0 To UBound(arNames)

  'if not default value
  If arNames(i) <> "" Then

   flagIgnore = False  'assume name not approved

   'retrieve the value as a string
   strValue = RtnValue (hHive, strKey, arNames(i), arType(i))
   'save the value type as a string
   strType = RtnType (arType(i))

   'compare name/value pair to approved names/values
   For j = 0 To UBound(arAllowedNames,1)

    'for approved name and value identical to abbreviated value or
    ' for any allowed value, toggle flag and exit
    If LCase(Trim(arNames(i))) = LCase(arAllowedNames(j,0)) Then

     If ((LCase(strAbbrevValue) = LCase(arAllowedNames(j,3))) Or _
      arAllowedNames(j,3) = "***") And Not flagShowAll Then

       flagIgnore = True : intISI = j : Exit For

     Else  'approved name, but unapproved value or ShowAll

      'form output string and write to file, avoid add'l output
      strGPLoc = strGPOT & arAllowedNames(j,1) & vbCRLF
      'reform line if policy not in GPedit.msc
      If InStr(LCase(arAllowedNames(j,1)),LCase("not in GPedit.msc")) > 0 Then _
       strGPLoc = arAllowedNames(j,1) & vbCRLF
      'if GP not used here or GP editor doesn't contain this value,
      'set location string to LBr
      If Not flagGP Or arAllowedNames(j,1) = "" Then strGPLoc = LBr
      TitleLineWrite

      oFN.WriteLine vbCRLF & arNames(i) & " = (" & strType & ") " &_
       strValue & vbCRLF & strGPLoc & arAllowedNames(j,2)
      flagIgnore = True

     End If  'approved value?

    End If  'approved name?

   Next  'arAllowedNames member

   'if name/value not approved
   If Not flagIgnore Then

    flagFound = False  'assume name not recognized

    'for every recognized name
    For j = 0 To UBound(arRecNames,1)

     'if name on recognized list, toggle flag and save array index
     If LCase(Trim(arNames(i))) = LCase(arRecNames(j,0)) Then
      flagFound = True : intKSI = j : Exit For
     End If

    Next  'recognized name array member

    If flagFound Then  'if name recognized

     'form output string and write to file
     strGPLoc = strGPOT & arRecNames(intKSI,1) & vbCRLF
     'if GP not used here or GP editor doesn't contain this value,
     'set location string to LBr
     If Not flagGP Or arRecNames(intKSI,1) = "" Then strGPLoc = LBr
     TitleLineWrite
     oFN.WriteLine vbCRLF & arNames(i) & " = (" & strType & ") " &_
     strValue & vbCRLF & strGPLoc & arRecNames(intKSI,2)

    Else  'name not recognized

     TitleLineWrite
     oFN.WriteLine vbCRLF & arNames(i) & " = (" & strType & ") " &_
      strValue & vbCRLF & "{unrecognized setting}"

    End If  'name recognized?

   End If  'not approved name/value?

  End If  'default name?

 Next  'next arNames member

'output reg-key title if absent or empty and ShowAll
ElseIf flagShowAll Then

 TitleLineWrite

End If  'reg key has values?

End Sub




Sub ReDimGPOArrays

ReDim arRecNames(0,0) : arRecNames(0,0) = ""
ReDim arAllowedNames(0,0) : arAllowedNames(0,0) = ""

End Sub




Function SecTest

Dim i

SecTest = False

'check section status if in testing mode
If flagTest Then

 For i = 0 To UBound(arSecTest)

  'if section number in arSecTest, toggle function
  If arSecTest(i) = intSection Then
   SecTest = True : Exit For
  End If  'this section in arSecTest?

 Next

End If  'flagTest?

End Function




Sub StrParse2Unique (strIn)

Dim i  'counter
Dim intStrLen : intStrLen = Len(strIn)  'input string Length
Dim cntChr : cntChr = 0  'number of chrs in executable string
Dim intStartChr : intStartChr = 1  'start of component name in string

'for every chr in input string
For i = 1 To intStrLen

 'if the chr is a delimiter
 If Mid(strIn,i,1) = " " Or Mid(strIn,i,1) = "," Then

  'if at least one non-delimiter chr has been encountered
  If cntChr > 0 Then

   AppUnique2DynArr strIn,intStartChr,cntChr
   intStartChr = i + 1  'reset the executable string start to next chr

  End If

 Else  'chr not a delimiter

  cntChr = cntChr + 1  'increment the exec string counter

 End If  'chr a delimiter?

Next  'line chr

'check the end-string
If cntChr > 0 Then

 AppUnique2DynArr strIn,intStartChr,cntChr

End If  'exec string found at end of line?

End Sub




'APPendUNIQUE2DYNamicARRay
Sub AppUnique2DynArr (strIn,intStart,intLen)

Dim i  'counter
Dim strCName : strCName = Mid(strIn,intStart,intLen)  'extract the component from the input string
intLen = 0  'reset the executable counter
Dim flagNew : flagNew = True  'true if extracted component not already in array

If intUB >= 0 Then

 For i = 0 To intUB

  If LCase(arAcc(i)) = LCase(strCName) Then
   flagNew = False : Exit For
  End If

 Next

End If

If flagNew Then

 intUB = intUB + 1 : ReDim Preserve arAcc(intUB)
 arAcc(intUB) = strCName  'add the component to the output array

End If

End Sub




'search for Print Monitor Driver File Name in \spool\prtprocs for
Sub PrtProcPM (strPMDFN, oDir)

'exit if no file name provided
If strPMDFN = "" Then Exit Sub

'file collection/member, sub-dir collection/member, error number
'Driver File Company Name
Dim colPPFi, oPPFi, colSF, oSF, intErrNum, strDFCN

'exit if driver already located in prtprocs
If flagInfect Then Exit Sub

'toggle flags if matching file name found in this folder
On Error Resume Next
 Set colPPFi = oDir.Files
 intErrNum = Err.Num : Err.Clear
On Error GoTo 0

If intErrNum = 0 Then  'if files found

 For Each oPPFi in colPPFi

  'is file name identical to driver name?
  If LCase(oPPFi.Name) = LCase(strPMDFN) Then

   'toggle flags if true
   flagIWarn = True : flagInfect = True

   'find CoName
   strDFCN = CoName(IDExe(oPPFi.Path))

   'append to output string and exit sub
   If strOut = "" Then
    strOut = " -- file found in " & oDir.Path & strDFCN
   Else
    strOut = strOut & vbCRLF & " -- file found in " & oDir.Path & strDFCN
   End If

   Exit Sub

  End If  'file name=driver name?

 Next  'file in this folder

Else  'error accessing files found in this folder

 If strOut = "" Then
  strOut = " Error accessing files in " & oDir.Path
 Else
  strOut = strOut & vbCRLF & " Error accessing files in " & oDir.Path
 End If

 'toggle flag & exit sub
 flagIWarn = True : flagInfect = True : Exit Sub

End If  'error accessing files in this folder?

'get sub-folder collection & trap any error (prob. due to permissions)
On Error Resume Next
 Set colSF = oDir.SubFolders
 intErrNum = Err.Number : Err.Clear
On Error GoTo 0

'if no error, recurse the sub-folders
If intErrNum = 0 Then

 For Each oSF In colSF : PrtProcPM strPMDFN, oSF : Next
 Set colSF=Nothing

Else  'output error

 If strOut = "" Then
  strOut = " Error accessing sub-folders in " & oDir.Path
 Else
  strOut = strOut & vbCRLF & " Error accessing sub-folders in " & oDir.Path
 End If

 flagIWarn = True : flagInfect = True : Exit Sub

End If  'error accessing subfolders?

End Sub




'SOftWare CAse
Function SOCA (strIn)

SOCA = strIn

If InStr(strIn,"HKCU\SOFTWARE") > 0 Then _
 SOCA = Replace(strIn,"HKCU\SOFTWARE","HKCU\Software")

If InStr(strIn,"HKLM\Software") > 0 And InStr(strOSLong,"Windows 98") = 0 Then
 SOCA = Replace(strIn,"HKLM\Software","HKLM\SOFTWARE")
ElseIf InStr(strIn,"HKLM\SOFTWARE") > 0 And InStr(strOSLong,"Windows 98") > 0 Then
 SOCA = Replace(strIn,"HKLM\SOFTWARE","HKLM\Software")
End If

End Function




'SYstem CAse
Function SYCA (strIn)

SYCA = strIn

If InStr(strIn,"HKLM\System") And strOS <> "W98" And strOS <> "WME" Then _
 SYCA = Replace(strIn,"HKLM\System","HKLM\SYSTEM")

If InStr(strIn,"HKLM\SYSTEM") And (strOS = "W98" Or strOS = "WME") Then _
 SYCA = Replace(strIn,"HKLM\SYSTEM","HKLM\System")

End Function




Function IsCLSID (strIn)

'{########-####-####-####-############}

IsCLSID = False  'assume false

Dim strWork, i
Dim arHexAlpha : arHexAlpha = Array("a","b","c","d","e","f")

'check length, first & last chrs
If Len(strIn) = 38 And Left(strIn,1) = "{" And Right(strIn,1) = "}" Then

 strWork = strIn

 'change all digits to 0
 For i = 1 To 9
  strWork = Replace (strWork,i,"0")
 Next

 'change all letters to 0
 For i = 0 To UBound(arHexAlpha)
  strWork = Replace (LCase(strWork),arHexAlpha(i),"0")
 Next

 'check replaced string, flip function value and exit
 If strWork = "{00000000-0000-0000-0000-000000000000}" Then
  IsCLSID = True : Exit Function
 End If

End If  'len, 1st/last chrs OK?

'exit with default value if land here

End Function




'hive/key enabler sum, hive array index, key array index
Function HKInclude (intMap, intHive, intKey)

 'returns True or False
 HKInclude = intMap And (2 ^ ((intHive * 1) + (intKey * 2)))

End Function




'R00
'initial rev. 2004-04-20

'R01
'avoided trailing backslash for ScrPath if path is drive root; added
'detection of W98 and HKLM... RunOnceEx, RunServices, RunServicesOnce;
'enumeration of RunOnceEx keys; error if WMI not installed with launch
'of browser to download site & message in text file

'R02
'minor report enhancements

'R03
'added computer name to report file name

'R04
'added:
'HKCU-HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load & run
'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell & Userinit
'HKLM\Software\Classes\[exe-type]file\shell\open\command
'WIN.INI [windows] load= & run=
'SYSTEM.INI [boot] shell=

'R05
'added:
'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
'HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
' value of name is CLSID whose InProcServer32 default name's value = executable
'omitted output if keys empty

'R06
'omitted all output if anomalies absent; added W98Titles & DefExeTitles
'functions

'R07
'added RegDataChk sub
'added:
'HKLM\Software\Microsoft\Active Setup\Installed Components\
'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler\
'HKCU & HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\
'HKCU & HKLM\Software\Microsoft\Command Processor\AutoRun
'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
'HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute

'R08
'removed:
'HKCU & HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\
'manages restricted/trusted sites, but not an executable launch point
'added MsgBox at script completion

'R09
'added identification of PIF target, converted script completion
'MsgBox to PopUp

'R10
'added VIII. shortcut parameters

'R11
'added length check for CLSID data, error handling for bad values
' & missing BHO InprocServer32 key
'added:
'WINSTART.BAT contents listing
'HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\

'R12
'added 10-line "unalterable" comments header
'added detected OS to output file (incl. WMe & WS2K3)
'changed terminology from "value/data" to "name/value"
'added to section I:
' arRegFlag array (for each OS: hive,key,execution applicability & warning flags)
' W98,WMe,NT4,W2K,WXP arRegFlag data
' EnumKeyData function for parsing of all value data types & display
'  in output file
' subkey recursion (for handling of W2K bug & HKCU/HKLM... RunOnce\Setup)
'removed from Section I:
' HKCU...RunServices & RunServicesOnce for W98
' HKCU... / HKLM... Explorer\Run for NT4

'R13
'added MsgBox to quit if WS2K3 detected
'added HKLM... Winlogon\Notify
'encoded MsgBox e-mail address in hex

'R14
'added INFECTION WARNING! for non-default Winlogon\Notify entry

'R15
'added default value as program's title to HKLM...Active
'Setup\Installed Components section

'R16
'corrected R07 comments concerning HKLM...BootExecute

'R17
'added detection of URL shortcuts in Start Menu folders

'R18
'changed attribution header to accommodate SE results
'added Echo output for CScript host
'added revision number to output file
'modified section II:
' list HKLM\Software\Microsoft\Active Setup\Installed Components\ if
' StubPath value exists and HKCU... Active Setup\Installed Components
' key does not exist, or if HKLM comma-delimited version number > HKCU
' version number
'added to section VI:
' HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell
' HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
'modified section X: suppressed startup folder title in output file if folder empty
'added section XI - enabled Scheduled Tasks
'redimmed arrays to 0 to recover memory at end of every section

'R19
'added to section X:
' %WINDIR%\All Users... Startup for W98
'in section XI:
' fixed executable statement parsing bug due to use of Asc instead of AscW
' changed enabled criterion to single byte (44)
'added revision number to MsgBox/Echo at EOJ

'R20
'added output file directory via argument
'added two sections & renumbered existing sections
'added tests for WMe in sections VI, VII, X, XI
'in section III:
' obtained BHO names from CLSID key if unavailable from BHO key
'added section VIII for W2K/WXP:
' HKCU/HKLM\Software\Policies\Microsoft\Windows\System\Scripts
'in section XI:
' excluded DESKTOP.INI files when present in startup directories,
' revised startup folder name title output to only occur if shortcut,
' PIF or executable found in folder
'in section XII:
' changed enabled criteria to single byte: 30h (48),
' bit 2 (0-based) = 0
'added section XIII: started service name, display name, path,
' CompanyName != Microsoft
'added functions: IDExe - extract service executable from path
'                 FLN - find leading script executable number
'                 ScrIP - SCRIPTS.INI parser
'                 CoName - find CompanyName in file

'R21
'added trap for VBScript version for W98/NT4
'added detection of W95 (interpreted as W98)
'added Err.Clear statement after every invocation of On Error Resume Next
'added script name to report header
'added namespace to WMI connection statement
'revised CoName function to concatenate several path strings and call
' 2nd function that uses WMI to retrieve co-name
'added functions: LRParse - parse load/run lines for executables
'                 CNCall - locate file in initial string, windows,
'                          system, app paths; retrieve co-name via WMI
'added co-name ID to all pgm sections
'removed output of value type from section I
'fixed bug in section VI - HKLM\...Winlogon\Userinit, infection alert
' was being issued when no comma in string
'changed BootExecute output in VI from output line for every
' multistring entry to single line

'R22
'fixed CNCall malformed path (leading backslash) bug, improved CNCall
'error handling; protected CoName from null or empty ImagePath strings
'due to deleted service left running

'R23
'changed strAUSUF to flagAUSUF in section XI
'added error handling for corrupt JOB file in section XII
'added function: JobFileRead
'changed "empty data" to "empty string" in CNCall
'added ".exe" to extension-less executable in JobFileRead

'R24
'revised R23 changes
'added back strTitleLine assignment in section XII

'R25
'added test for arHKCUKeys array in HKCU... Active Setup\Installed
' Components (section II)
'DIMed local variables in AppPath to avoid conflict with strValue used
' in Section VI; fixed same bug in IniLRS
'suppressed section title if both startup folders empty in section XI

'R26
'changed endpoint in services sort in section XIII so that sort
' included last service in initial array

'R27
'declared strFPSF & strFPWF Public (used in CoName sub)
'script host bug workaround: in some script versions,
' CreateTextFile/OpenTextFile with Create parameter=True overwrites
' file contents line by line instead of overwriting file, so now delete
' output file if it exists before writing to it
'added trap for CreateTextFile error
'added colons to all section titles
'added comments to better explain array in section I
'added to section V: HKCU...ShellServiceObjectDelayLoad
'added to section VI: GinaDLL
'added to section VII: Notify values for W2K (termsrv) & WS2K3 (=WXP)
'new section XI: AUTORUN.INF in root of fixed disks, renumbered XII-XIV
'added functions: NDTAR, NDAR, FmtTime
'changed function titles: W98Titles -> IniInfTitles; IniLRS -> IniInfParse
'modified function RegDataChk to handle no value or empty+expected value
'added script launch time to output file header

'R28
'new section IV: HKLM...Shell Extensions\Approved, renumbered V-XV
'restricted output in sections II, V, XIV
'added flagShowAll and "-all" command line parameter
'added header and footer comments, {++} indicator in non-default mode
' for HKCU/HKLM...Run keys
'subkey enumeration (EnumKey) via IsArray followed by For Each
'enabled WS2K3 operation, extended final popup to 5 seconds

'R29
'redirected browser to RED version in case of CreateTextFile error
'appended wscsvc to arMSSvc for WXP
'checked for null string returned by oReg.GetStringValue
'fixed bug under XP for script not stored in default script directory --
' CoName was always "file not found"
'in Section II (HKLM... Active Setup\Installed Components), avoid code
' section if HKLM Version name doesn't exist or value not set (exc for (W2K!)
'in Section III (HKLM... Explorer\Browser Helper Objects\), avoid
' output if InProcServer32 default value not set
'in Section V (HKLM... Explorer\SharedTaskScheduler), avoid code if
' IPS doesn't exist
'rewrote IDExe & revised CoName functions, eliminated CNCall

'R30
'added FmtHMS function, removed FmtTime function
'added hh.mm.ss to report file name
'use unique time for report title, removed launch time from report header
'default flagOut = "C" if neither WSCRIPT nor CSCRIPT detected
'in Section XIII, for executable in SU directory, send Path to IDExe
' instead of Name
'in IDExe & WSL functions, return Path property of GetFile object so path
' included if file located in VBS CurrentDirectory
'standardized CLSID InProcServer32 output line in Sections III, IV, V, VI to:
' "  -> {CLSID}\InProcServer32\(Default) = "

'R31
'added instructions for WXP if Fso connection fails
'added instructions for W2K/WXP if WMI connection fails
'added StringFilter function to filter unwritable default values
'added to section VII: Policies\System\Shell for W2K
'added to section X: cmd, scr; added arExpVal (expected value array);
' get filetype from extension default value and check filetype
' shell\open\command
'removed DefExeTitles function
'added section XI: scrnsave.exe for NT4/W2K/WXP
'added to section XII: scrnsave.exe in SYSTEM.INI
'added section XVII: Winsock2 Service Provider DLLs
'modified IDExe to use common environment variables
'added section XVIII: IE URL prefixes

'R31.1
'added home page URL to report header

'R32
'removed quotes surrounding key\value name output in following sections:
' HKLM... Active Setup\Installed Components
' HKLM...Winlogon\Notify\
'added section X: HKCR\Protocols\Filter
'modified output format in Screen Saver section

'R33
'section II: HKLM-to-HKCU Active Setup/Installed Components key names
' made non-case-specific
'added to section VII: Winlogon\Taskman
'added to section XII: Wallpaper
'allowed URL\Prefixes names to contain trailing periods
'moved Services to next-to-last section (XX)
'trapped error & quit if running services can't be counted
'added section XIX: HOSTS
'added section XXI: Keyboard Driver Filters
'added sub: SRClose

'R34
'added section XVIII: Toolbars, Explorer Bars (active & dormant), Extensions
'section XX: detect tabs [Chr(09)] in addition to spaces as HOSTS file delimiter
'section XXI: moved DIM of two variables to main (errors not thrown
' by Option Explicit!)
'added flagPad to StringFilter function
'retrieved all InProcServer32 default values via GetExpandedStringValue
' instead of GetStringValue

'R35
'revised R34 notes
'introduced MS constant
'section V: added HKLM...Explorer\ShellExecuteHooks, modified allowed
' logic
'section VIII: added "&Discuss" to allowed Explorer Bars
'section XV: added INFECTION WARNING if executable located in startup directory
'changed flagPad to flagEmbedQ in StringFilter function

'R36
'added flagTest
'added section IX: HKLM...Windows NT\CurrentVersion\Image File Execution Options
'section XXI: checked HOSTS file location at HKLM...Tcpip\Parameters\DataBasePath

'R37
'added W95 & WMe compatibility
'sections III & XX: if ShowAll, write section titles if hive keys absent
'added section XIII: System/Group Policies
'moved wallpaper ahead of screen saver in section XIV
'in RegDataChk, sent "shell" line to LRParse for ID of malware CoName

'R38
'added script startup popup
'replaced EnumKeyData with EnumNVP and RtnValue functions, renamed
' ScrIP to ScrIFP
'added IERESETCounter, ResolveCLSID, TitleLineWrite functions
'section XIII: added Control Panel applet removal + 2 toolbar entries
' to Explorer values; added Policies\Microsoft\Internet Explorer
' subsection
'section XX (IE Toolbars, Explorer Bars, Extensions): moved CLSID
' titles (default values) to the CLSID line
'added section XXII: misc IE hijack points (IERESET.INF,
' URLSearchHooks, AboutURLS)
'section XXIII: detect tabs preceding spaces as HOST file delimiters
'added "--" tail to ShowAll report
'removed Messenger from allowed IE extensions (Messenger has
' vulnerable versions)

'R38.1
'section XXII: determined IERESET.INF format by reading 1st 2 chrs
'before opening to compare with local copy

'R39
'performed housekeeping on all opened objects
'section XIII: added Explorer\NoFolderOptions, NoWindowsUpdate,
' and DisableWindowsUpdateAccess; HKLM... Windows NT\SystemRestore
'added section XII: context menu shell extensions
'added section XVIII: DESKTOP.INI in local fixed drive directory
'added -supp command line parameter to skip DESKTOP.INI and dormant
' Explorer Bar sections
'SRClose: added -supp advisory and reformatted
'section XXIV: added IERESET.INF minimum size requirement
'section XXVI: added 5 services for W2KS & 1 for WXP
'report footer: added total run time, DESKTOP.INI folder search time,
' dormant Explorer Bar search time
'added popup to select -supp parameter
'fixed intMB Dim placement bug

'R40
'moved WMI installation detection after VBScript version & OS version
' detection
'switched supp search msgbox buttons so that "Yes" is default instead of "No"
'suppressed menu display time when using CSCRIPT.EXE
'section XIV: for WXP SP2, added NoExtensionManagement
'section XVIII: trapped error if letter assigned to RAW data
' (ex: Linux) partition
'section XXIV: added On Error trap for IERESET.INF lines
'function IDExe: simplified use of ExpandEnvironmentStrings
'function CoName: added StringFilter for Unicode names

'R40.1
'edited SRClose footer to cite pressing "No" instead of "Yes" at first
'msgbox for -supp option

'R41
'section VII: check for existence of BootExecute value before
' validating
'added section XXVIII: Print Monitors

'R42
'added WINVER.EXE file version for W95 SR2 (OEM)
'lengthened final Popup time from 5 to 20 seconds

'R43
'section XII: added HKLM... Control\SafeBoot\Option\UseAlternateShell

'R44
'sections III-IV-V-VI-XI-XII-XVIII-XXII-XXIV: modified CLSID\InProcServer32
' search to use HKCU, then HKLM
'section XI: modified Classes\PROTOCOLS\Filter search to use HKCU, then HKLM
'section XII: added ColumnHandlers
'section XIII: rewrote to output non-default values in HKCU/HKLM
'section XXV: improved function logic, added ExpandEnvironmentStrings
' to DataBasePath value
'added SOCValue sub and StrOutCR function
'WriteValueData function: protected strName with StringFilter
'CoName function: removed StringFilter for findable file with Unicode name

'R45
'added colOS WMI error trap
'section VII: added WOW\cmdline and WOW\wowcmdline values
'modified function RegDataChk to handle empty string or missing
' name/value pair
'changed "(no data)" to "(value not found)"

'R46
'section VII: removed output of BootExecute strLine on WriteLine error
'section XIII, SOCValue sub: added check for shell default value
'added DDEX sub to look for open\ddeexec value in SOCValue sub

'R47
'section VIII: added wgalogon to Winlogon\Notify allowed entries
'section XIII: output default executable string via StringFilter
'section XXI: arTSPFi (TSP output array) initial REDIM statement
' changed from (2,0) to (3,0)
'section XXVI: tested service pathname returned by WMI for null or
' empty string before storing in array
'for compatibility with IE 7 RC1, modified sections:
'   IV (Shell Extensions)
'    V (SharedTaskScheduler)
' XXIV (bypass of IERESET.INF check, AboutURLs)

'R48
'section VII: added HKLM\System\CurrentControlSet\Control\SecurityProviders\SecurityProviders

'R49
'added message box to confirm choice of supplementary search
'added IWarn/HWarn strings with explanatory footer note if present
'abandoned roman numerals for section numbers
'added SecTest for section testing
'changed OS version error e-mail address
'section 1: added W95-specific matrix; HKCU...RunOnceEx for all OS's
' Policies/Explorer/Run for WMe, Run/RunOnce subkey launch for WMe,
' removed Policies/Explorer/Run & RunOnce/Setup warnings for NT4
'section 12: added AllFilesystemObjects
'section 14: removed Policy hierarchization, added registry
' keys, added GPRCaller and GPReconizer subs
'section 15: due to Policy hierarchization changes, lost detection of
' Active Desktop status
'section 20: added XML parsing for WVa
'section 22: restored "dormant" IE explorer bars to default
' operation, removed "dormant" label
'RtnValue function fixed for REG_BINARY & REG_MULTI_SZ, added REG_QWORD
'StrOutCR function renamed to StrOutSep, 3rd arg is sep character
'all sections: ensured compatibility with Vista RC1

'R50
'section 10: added FileSysPath to script directory even if script file
' not found (due to disconnection from domain)
'section 13: added StringFilter to every occurrence of strOut in
' SOCValue & DDEX subs
'section 26: added WXP httpfilter service

'R51
'renamed "Vista RC1" to "Vista"
'section 19: checked for error on retrieval of startup folders
'added script launch time to report footer

'R52
'protected NDAR/NDTAR from corrupt binary values

'R53
'modified section titles to match top comments section
'updated Configuration Detection Section line numbers
'section 13: added HKCU FileExt loop for WMe/W2K/WXP, modified main loop logic
'section 26: removed UtilMan from W2K default list, added 3 services
' to WVa default list
'added section 27: Accessibility Tools
'modified RtnValue function (DWORD value displays "dword:" instead of "hex:"),
' StringFilter function, SOCValue Sub

'R54
'section 7: added HKLM... Windows NT... Aedebug
'section 27: toggled flagIWarn for report footer
'capitalized HKLM\Software if HKCU\Software unaffected

'R55
'section 4: added 30 shell extensions from Vista Home Premium
'section 7: revised Winlogon name/value logic, added Winlogon\VmApplet
'section 26: removed 1 duplicate Vista service, improved Vista ServiceDll identification
'added functions SOCA/SYCA to manage display of "Software" & "System"
'replaced Chr(34) by DQ

'R56
'section 7: added HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram\ImagePath
'                 HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
'                 HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Execute
'                 HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SetupExecute
'section 25: treated "::1" as localhost
'modified RtnValue function (returns "value not set" if registry read
' throws error)
'replaced RegDataChk sub with RegDataChk_v2

'R57
'made testing alert sensitive to flagOut
'changed strOS to Public variable
'section 5: added Explorer\DeviceNotificationCallbacks\ for WVa
'added section 18: HKLM... Explorer\AutoplayHandlers\Handlers\
'section 27: added Network Provisioning Service (xmlprov.dll) to default XP services
'added IsCLSID & CLSIDPop functions
'rewrote SOCA/SYCA functions

'R58
'section 16: added IniFileMapping
'StringFilter function: trap Asc = 160 as corrupt character
'added ChkDefaultValue & ChkNameValues subs

'R59
'section 7: added HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
'section 8: added dimsntfy.dll (DIMS Notification Handler) to default array arSK()

'R60
'EnumNVP sub renamed to EnumNT (enumerate names & types)
'RegDataChk_v2 sub revised, fixed bug that excluded AppInit_DLLs
'added automatic relaunch with admin rights under WVa & Wn7
'added detection of service pack number
'added new line before CLSID title lines in sections 3, 4, 5, 6, 7, 13, 14, 26
'added section 4: added Explorer\ShellIconOverlayIdentifiers
'section  8: added Control\ServiceControlManagerExtension, Control\Lsa\Security Packages,
' Control\SecurityProviders\SecurityProviders
'added section 9: HKLM... Authentication\Credential Provider Filters/Credential Providers
'section 13: added PROTOCOLS\Handler
'section 14: added CopyHookHandlers, DragDropHandlers, PropertySheetHandlers
'added section 23: WVa/Wn7 Sidebar Gadgets
'fixed bugs: section 16 (ReDimGPOArrays), section 30 (InStrRev(IDExe(... ),
'removed IsArray tests on dynamic arrays and restricted their use
'all sections: ensured compatibility with Windows 7 RC1
'updated Configuration Detection Section line numbers

'R61
'documentary comments placed in proximity at top of script
'removed output to report file in case of WMI connection error
'removed ReDim statements for static arrays
'added section 31: Safe Mode Drivers & Services
'added use of WScript.FullName as ShellExecute executable
'added detection of elevated privileges under WVa/Wn7 to avoid ShellExecute relaunch
'added check for WHOAMI.EXE and results file, quit if either not found

'R62
'In case of FileSystemObject creation error, WScript 5.7 d/l loc'n for
'WXP switched from TinyURL to bit.ly
'section 15: dictionary added for progid name/value pairs,
'UserChoice added for WVa/Wn7
'section 16: fixed text display bug if policy not in GPedit.msc
'all sections: ensured compatibility with Windows Server 2003 (added
'separate array for WS2K3 in Started Services section 30)
'GPRecognizer Sub: added protection for unwritable string

'R63
'all sections: ensured compatibility with Windows NT 4.0 Server and
'Windows 2000 Server

'R64
'added compatibility with 64-bit OS versions
'added Windows Server 2008 R2 (64-bit)
'changed report file format to Unicode, deleted StringFilter function
'changed reporting of OS version from WINVER.EXE file version to WMI
'changed method of determining elevated privileges under WVa & Wn7
'removed enclosing quotes in report, replaced "..." ellipsis with single chr
'fixed report output directory argument bug
'added HKInclude function, PrtProcPM sub
'declared oReg as Public variable
'fixed bugs in RtnValue sub -- replaced intErrNum by local intFErrNum,
' registry reads of garbage data intermittently threw WSH Provider
' Failure error code 80041004
'protected _all_ registry value reads within On Error shields
'section  2: simplified search of HKLM key in HKCU
'section  5: added HKCU
'section  8: revised Notification Packages/Security Packages loop
'section  9: added PLAP Providers
'section 16: added HKLM allowed ActiveDesktop settings
'section 34: added search for print monitor driver in prtprocs tree

'R65
'added compatibility with Wn8
'added BS (BackSlash) constant
'sections 5, 8, 9, 26, 30, 31: supplemented for Wn8
'section 14: added search for 32-bit (WOW6432Node) CLSIDs for 64-bit
' shell extensions
'section 15: for ShowAll, display FileExts and extension output if key
' not found
'section 16: added "Force specific screen saver" to GPs
'section 24: in ESTParse, added optional addition of braces around
' ClassID if not initially recognized as CLSID
'section 25: added recursion for subkeys of Current_NameSpace_Catalog &
' Current_Protocol_Catalog key names
'section 33: reset infection warning for each kb filter value
'section 34: revised spool path for WME

'R66
'section 14: corrected search for 32-bit shell extensions in
' SOFTWARE\Wow6432node instead of SOFTWARE\Wow3264node

'R67
'added R66 change history to script footer

'R68
'section  5: added approved shell extension for WS2K3
'section  7: added ShellServiceObjectDelayLoad DLL for WXP x64
'section  8: added SecurityProvider for WS2K8
'section 14: added CopyHookHandler for W98
'section 23: avoided output if Sidebar Settings.ini file not found
'section 25: suppressed display of " {++}" for ShowAll
'section 30: added default services for WS2K3, WXP x64, WVA x64, and WS2K8
'section 33: fixed infection warning due to InStr comparison
'added " {++}" to subtitles of sections 22, 23 & 24 unless ShowAll
'TitleLineWrite sub: " {++}" not underlined if present in Title string

'R69
'section  8: relabeled 64-bit Classes branch in output title for
' Command Processor
'section 14: fixed 64-bit Classes branch in searched registry key
'section 15: rewritten
'section 26: changed 64-bit Classes branch from
' Software\Wow6432Node\Classes to Software\Classes\Wow6432Node (better
' compatiblity with WVa)
'section 30: added default Safe Mode services; merged WS2K3 service
' list with WXP
'SOCValue sub replaced by CLAnal
'added CLSID_ID sub
'ResolveCLSID, DTIParse, ESTParse subs: same change as in section 26

'R69.1
'changed the LIP constant to 3 periods

'R69.2
'cosmetic revision: adjusted spacing to align CLSIDs with 2 extra
'LIP-constant characters

'R70
'added compatibility with W10
'changed W98 SE identification method
'sections renumbered! (two added)
'section  1: added HKLM...Wow6432Node...RunOnceEx
'            added HKLM...Wow6432Node...Polices\Explorer\Run
'            (mirror of HKLM...Polices\Explorer\Run)
'section  2: W10 bug! Installed Components =
'            ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95}", HKLM StubPath
'            points to \inf but HKCU StubPath points to system32
'section  5: HKCU/HKLM/HKLM-WOW... Explorer\ShellServiceObjects -- new section
'section  7: fixed bad counter variable, switched from "i" to "intKey"
'section  8: added output for flagShowAll
'section  9: Aedebug applied to NT4+, expected value for "Auto" set to
'            empty string
'section 11: added check of value data & CoName for W2K default name
'section 12: HKLM... Windows NT... Winlogon\GPExtensions -- new section
'section 16: removed HKLM requirement for allowed DLL
'            added Folder\ShellEx\ExtShellFolderViews
'section 32: consolidated WVA with WN7
'WriteValueData function revised to omit CoName for "Title" values
'CoName(IDExe()) removed from loops via preceding strCN assignment
'statements

'R71
'section 32: added 2 Passport-related services for W10
'accomodation of W10 v1703 (Creators Update)
'section 10: added 7 Authentication\Credential Providers

'R72 (W10 v1709 Fall Creators Update)
'section 10: added 2 Authentication\Credential Providers
'section 12: added 8 Winlogon\GPExtensions
'section 16: added 1 ContextMenuHandler
'section 18: added 1 AllowedNames to HKLM... Policies\Explorer
'            added 4 AllowedNames to HKLM... Windows Error Reporting
'            added 6 RecNames     to HKLM... Policies\System
'section 32: added 3 services


'** Update Revision Number on line #15 **
