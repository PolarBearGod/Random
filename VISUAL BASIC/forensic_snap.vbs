Set WshShell = CreateObject("WScript.Shell")
strRegValue = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Hostname"
strHost = WshShell.RegRead( strRegValue )
strLocalOutput = "C:\Windows\Temp"
'RemoteOutput needs trailing slash!
strRemoteOutput = "C:\Users\Public\Desktop\output\"


''''''''''''''''''''''''''''''''''''''''''''''''''''''''
	'Define commands to be run
strFindServ = "HKEY_LOCAL_MACHINE ImagePath DisplayName ServiceDLL"
strImageEx = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
strAppXP = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility"
strApp7 = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
strAutoTSComLoc = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run"
strAutoTSRunOnceComLoc = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce"
strRegWinLogonUserInitLoc = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
strRegWinLogonShellLoc = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
strRegWinLogonTaskmanLoc = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman"
strRegExplorerBHOLoc = "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
strWowExplorerBHOLoc = "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
strRegSessionMgrBootExecLoc = "HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute"
strRegSessionMgrAppCertLoc = "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
strRegStartupDirLoc = "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
strRegProgDataStartupDirLoc = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
strRegVulnIELoc = "HKLM\SOFTWARE\Microsoft\Internet Explorer"
strVulnJavaLoc = "C:\Program Files*\Java\"
strVulnAdobeReadLoc = "'C:\\Program Files*\\Adobe\\Reader *\\Reader\\AcroRd32.exe'"
strVulnAdobeAcroLoc = "'C:\\Program Files*\\Adobe\\Acrobat *\\Acrobat\\Acrobat.exe'"
strProcCommand = "%comspec% /c wmic process get Caption,CommandLine,CSName,ExecutablePath,Handle,ParentProcessID,ProcessID,CreationDate,priority /format:list > " & strLocalOutput & "\" & strHost & "_systemprocesses.security"
strSizeCommand = "%comspec% /c wmic partition get name, bootable, size, type /format:csv > " & strLocalOutput & "\" & strHost & "_size.security"
strOSCommand = "%comspec% /c wmic os get version, caption, name, registereduser, installdate /format:csv > " & strLocalOutput & "\" & strHost & "_os.security"
strSysCommand = "%comspec% /c WMIC computersystem get name, domain, username /format:csv > " & strLocalOutput & "\" & strHost & "_system.security" 
strSrvCommand = "%comspec% /c wmic service get /format:list > " & strLocalOutput & "\" & strHost & "_services.security"
strStartCommand = "%comspec% /c wmic startup list full /format:csv > " & strLocalOutput & "\" & strHost & "_startuplistfull.security"
strNetCommand = "%comspec% /c netstat -ano > " & strLocalOutput & "\" & strHost & "_netstat.security"
strSchCommand = "%comspec% /c schtasks /query /v /fo list > " & strLocalOutput & "\" & strHost & "_schtasks.security"
strTskCommand = "%comspec% /c tasklist -m -fo csv > " & strLocalOutput & "\" & strHost & "_tasklist_dll.security"
strTskDLLCommand = "%comspec% /c tasklist -v > " & strLocalOutput & "\" & strHost & "_tasklist.security"
strDNSCommand = "%comspec% /c ipconfig /displaydns > " & strLocalOutput & "\" & strHost & "_displaydns.security"
strQUseCommand = "%comspec% /c quser > " & strLocalOutput & "\" & strHost & "_quser.security"
strWinCommand = "%comspec% /c REG QUERY HKLM\Software\Windows\CurrentVersion\ /s > " & strLocalOutput & "\" & strHost & "_reg_match_win_currver.security"
strAutoCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strAutoTSCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strAutoTSRunOnceCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strRunCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strCurrRunCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strRunOnceCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strWowRunCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strWowRunOnceCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strWowProcRunCommand = "%comspec% /c REG QUERY HKLM\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
strRegServicesCommand = "%comspec% /c REG QUERY HKLM\SYSTEM\CurrentControlSet\services\ /s | findstr /i """ & strFindServ & """ > " & strLocalOutput & "\" & strHost & "_reg_services.security"
strRegServices001Command = "%comspec% /c REG QUERY HKLM\SYSTEM\ControlSet001\services\ /s | findstr /i """ & strFindServ & """ >> " & strLocalOutput & "\" & strHost & "_reg_services.security"
strRegServices002Command = "%comspec% /c REG QUERY HKLM\SYSTEM\ControlSet002\services\ /s | findstr /i """ & strFindServ & """ >> " & strLocalOutput & "\" & strHost & "_reg_services.security"
strLegacyDriversCommand = "%comspec% /c REG QUERY HKLM\SYSTEM\CurrentControlSet\Enum\Root\ /s > " & strLocalOutput & "\" & strHost & "_legacy_drivers.security"
strLegacyDrivers001Command = "%comspec% /c REG QUERY HKLM\SYSTEM\ControlSet001\Enum\Root\ /s >> " & strLocalOutput & "\" & strHost & "_legacy_drivers.security"
strLegacyDrivers002Command = "%comspec% /c REG QUERY HKLM\SYSTEM\ControlSet002\Enum\Root\ /s >> " & strLocalOutput & "\" & strHost & "_legacy_drivers.security"
strServiceDriversCommand = "%comspec% /c REG QUERY HKLM\SYSTEM\CurrentControlSet\services\ /s | findstr /i """ & strFindServ & """ > " & strLocalOutput & "\" & strHost & "_service_drivers.security"
strImageExec = "%comspec% /c REG QUERY """ & strImageEx & """ /s >> " & strLocalOutput & "\" & strHost & "_reg_image_execution.security"
strAppCompatXP = "%comspec% /c REG QUERY """ & strAppXP & """ /s > " & strLocalOutput & "\" & strHost & "_reg_appcompat.security"
strAppCompat7 = "%comspec% /c REG QUERY """ & strApp7 & """ /s >> " & strLocalOutput & "\" & strHost & "_reg_appcompat.security"
strRegExplorerRunCommand = "%comspec% /c REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s >> """ & strLocalOutput & "\" &  strHost & "_reg_autorun.security"""
strRegWinLogonUserInitCommand = "%comspec% /c REG QUERY """ & strRegWinLogonUserInitLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegWinLogonShellCommand = "%comspec% /c REG QUERY """ & strRegWinLogonShellLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegWinLogonTaskmanCommand = "%comspec% /c REG QUERY """ & strRegWinLogonTaskmanLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegExplorerBHOCommand = "%comspec% /c REG QUERY """ & strRegExplorerBHOLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strWowExplorerBHOCommand = "%comspec% /c REG QUERY """ & strWowExplorerBHOLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegSessionMgrBootExecCommand = "%comspec% /c REG QUERY """ & strRegSessionMgrBootExecLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegSessionMgrAppCertCommand = "%comspec% /c REG QUERY """ & strRegSessionMgrAppCertLoc & """ /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strRegBootVerProgCommand = "%comspec% /c REG QUERY HKLM\System\CurrentControlSet\Control\BootVerificationProgram\ImagePath /s >> """ & strLocalOutput & "\" & strHost & "_reg_autorun.security"""
strPrefetchCommand = "%comspec% /c DIR /B /S C:\Windows\Prefetch >> """ & strLocalOutput & strHost & "_prefetch.security"""
strWinTempCommand = "%comspec% /c DIR /B /S C:\Windows\Temp > """ & strLocalOutput & "\" & strHost & "_temp_files.security"""
strRootTempCommand = "%comspec% /c DIR /B /S C:\Temp >> """ & strLocalOutput & "\" & strHost & "_temp_files.security"""
strRegStartupDirCommand = "%comspec% /c DIR /B /S """ & strRegStartupDirLoc & " > """ & strLocalOutput & "\" & strHost & "_reg_startup_files.security"""
strRegProgDataStartupDirCommand = "%comspec% /c DIR /B /S """ & strRegProgDataStartupDirLoc & " >> """ & strLocalOutput & "\" & strHost & "_reg_startup_files.security"""
strRegVulnIECommand = "%comspec% /c REG QUERY """ & strRegVulnIELoc & """  /v svcVersion > """ & strLocalOutput & "\" & strHost & "_IE_vuln.security"""
strVulnJavaCommand = "%comspec% /c DIR /B /S """ & strVulnJavaLoc & """ | findstr java.exe > """ & strLocalOutput & "\" & strHost & "_Java_vuln.security"""
strVulnFlashCommand = "%comspec% /c DIR /B C:\Windows\SysWow64\Macromed\Flash\FlashPlayerPlugin*.exe > """ & strLocalOutput & "\" & strHost & "_Flash_Vuln.security"""
strVulnAdobeReadCommand = "%comspec% /c WMIC datafile where ""name =" & strVulnAdobeReadLoc & """ get version >> """ & strLocalOutput & "\" & strhost & "_Reader.security"""
strVulnAdobeAcroCommand = "%comspec% /c WMIC datafile where ""name =" & strVulnAdobeAcroLoc & """ get version >> """ & strLocalOutput & "\" & strhost & "_Acrobat.security"""


''''''''''''''''''''''''''''''''''''''''''''''''''''''''
	'Run the bulk of BIT Commands
WshShell.Run strProcCommand, 0, True
WshShell.Run strSizeCommand, 0, True
WshShell.Run strOSCommand, 0, True
WshShell.Run strSysCommand, 0, True
WshShell.Run strSrvCommand, 0, True
WshShell.Run strStartCommand, 0, True
WshShell.Run strNetCommand, 0, True
WshShell.Run strSchCommand, 0, True
WshShell.Run strTskCommand, 0, True
WshShell.Run strTskDLLCommand, 0, True
WshShell.Run strDNSCommand, 0, True
WshShell.Run strQUseCommand, 0, True
WshShell.Run strWinCommand, 0, True
WshShell.Run strAutoCommand, 0, True
WshShell.Run strAutoTSCommand, 0, True
WshShell.Run strAutoTSRunOnceCommand, 0, True
WshShell.Run strRunCommand, 0, True
WshShell.Run strCurrRunCommand, 0, True
WshShell.Run strRunOnceCommand, 0, True
WshShell.Run strWowRunCommand, 0, True
WshShell.Run strWowRunOnceCommand, 0, True
WshShell.Run strWowProcRunCommand, 0, True
WshShell.Run strRegServicesCommand, 0, True
WshShell.Run strRegServices001Command, 0, True
WshShell.Run strRegServices002Command, 0, True
WshShell.Run strLegacyDriversCommand, 0, True
WshShell.Run strLegacyDrivers001Command, 0, True
WshShell.Run strLegacyDrivers002Command, 0, True
WshShell.Run strServiceDriversCommand, 0, True
WshShell.Run strImageExec, 0, True
WshShell.Run strAppCompatXP, 0, True
WshShell.Run strAppCompat7, 0, True
WshShell.Run strRegExplorerRunCommand, 0, True
WshShell.Run strRegWinLogonUserInitCommand, 0, True
WshShell.Run strRegWinLogonShellCommand, 0, True
WshShell.Run strRegWinLogonTaskmanCommand, 0, True
WshShell.Run strRegExplorerBHOCommand, 0, True
WshShell.Run strWowExplorerBHOCommand, 0, True 
WshShell.Run strRegSessionMgrBootExecCommand, 0, True
WshShell.Run strRegSessionMgrAppCertCommand, 0, True
WshShell.Run strRegBootVerProgCommand, 0, True
WshShell.Run strPrefetchCommand, 0, True
WshShell.Run strWinTempCommand, 0, True
WshShell.Run strRootTempCommand, 0, True
WshShell.Run strRegStartupDirCommand, 0, True
WshShell.Run strRegProgDataStartupDirCommand, 0, True
WshShell.Run strRegVulnIECommand, 0, True
WshShell.Run strVulnJavaCommand, 0, True
WshShell.Run strVulnFlashCommand, 0, True
WshShell.Run strVulnAdobeAcroCommand, 0, True
WshShell.Run strVulnAdobeReadCommand, 0, True

''''''''''''''''''''''''''''''''''''''''''''''''''''''''
	'Hash DLLs and EXEs
hashRunningProcs strHost, strLocalOutput
hashLoadedMods strHost, strLocalOutput

Dim fso, f, f1, fc
Set fso = CreateObject("Scripting.FileSystemObject") 

''''''''''''''''''''''''''''''''''''''''''''''''''''''''
	'Recurse profile GUIDs
strProfRegLoc = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"
strProfileList = "%comspec% /c reg query """ & strProfRegLoc & """ /s /v ProfileImagePath | findstr /i """ & "S-1-5-21" & """"
strProfileListOutput = "%comspec% /c reg query """ & strProfRegLoc & """ /s /v ProfileImagePath > " & strLocalOutput & "\" & strHost & "_ref_profiles.security"
WshShell.Run strProfileListOutput, 0, True

Set readProfiles = fso.OpenTextFile(strLocalOutput & "\" & strHost & "_ref_profiles.security", 1)
rawReadProfiles = readProfiles.ReadAll
readProfiles.Close
arrProfiles = Split(rawReadProfiles,vbNewLine)

profileCount = 0
For Each x in arrProfiles
	If len(x) > 1 Then
		If InStr(x,"HKEY_LOCAL_MACHINE") > 0 Then
			curSID = Replace(x,"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\","")
			If Left(curSID,8) = "S-1-5-21" Then
				profileCount = 1
			Else
				profileCount = 0
			End If
		ElseIf profileCount = 1 And InStr(x,"ProfileImagePath") > 0 Then
			arrProfile = Split(x,"\")
			For Each j in arrProfile
				If len(j) > 1 Then
					userName = trim(j)
				End If
			Next
			strTSLoc = "HKU\" & curSID & "\Software\Microsoft\Terminal Server Client\Servers"
			strUserAssistCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist /s > " & strLocalOutput & "\" & strHost & "_" & userName & "_userassist.security"
			strUserRunMRUCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /s > " & strLocalOutput & "\" & strHost & "_" & userName & "_runMRU.security"
			strUserRecentDocsCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs /s > " & strLocalOutput & "\" & strHost & "_" & userName & "_recentDocs.security"
			strUserTSServersCommand = "%comspec% /c REG QUERY """ & strTSLoc & """ /s > " & strLocalOutput & "\" & strHost & "_" & userName & "_TSservers.security"
			strUserAutoCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserAutoTSCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserAutoTSRunOnceCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserRunCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserCurrRunCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserRunOnceCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserWowRunCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserWowRunOnceCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"
			strUserWowProcRunCommand = "%comspec% /c REG QUERY HKU\" & curSID & "\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s >> " & strLocalOutput & "\" & strHost & "_reg_autorun.security"

			WshShell.Run strUserRecentDocsCommand, 0, True
			WshShell.Run strUserAssistCommand, 0, True
			WshShell.Run strUserRunMRUCommand, 0, True
			WshShell.Run strUserTSServersCommand, 0, True
			WshShell.Run strUserAutoCommand, 0, True
			WshShell.Run strUserAutoTSCommand, 0, True
			WshShell.Run strUserAutoTSRunOnceCommand, 0, True
			WshShell.Run strUserRunCommand, 0, True
			WshShell.Run strUserCurrRunCommand, 0, True
			WshShell.Run strUserRunOnceCommand, 0, True
			WshShell.Run strUserWowRunCommand, 0, True
			WshShell.Run strUserWowRunOnceCommand, 0, True
			WshShell.Run strUserWowProcRunCommand, 0, True
			profileCount = 0
		End If
	End If
Next

''''''''''''''''''''''''''''''''''''''''''''''''''''''''
Dim filename
If right(strLocalOutput, 1) = "\" Then
	filename = strLocalOutput & strHost & ".zip"	
Else
	filename = strLocalOutput & "\" & strHost & ".zip"	
End If

ZipFolder fso.GetAbsolutePathName(strLocalOutput), filename

	'Now move the output
'If right(strRemoteOutput,1) <> "\" Then
	'strRemoteOutput = strRemoteOutput & "\"
'End If

Set f = fso.GetFolder(strLocalOutput) 
Set fc = f.Files 
For Each f1 in fc 
 If fso.getextensionname(f1) = "security" Then
	fso.DeleteFile f1
 End If
Next 

'fso.MoveFile filename, strRemoteOutput

Function hashRunningProcs(strComputer, strOutputFolder)
	Dim objWMIService, objProcess, colProcess, objSWbemLocator

	'Get all running process through WMI
	Dim illegalList, currenProcessHash
	'WSCript.Echo "Getting all running process for - " & strComputer & " ..."

	Set objSWbemLocator = CreateObject("WbemScripting.SWbemLocator")
	If Err <> 0 Then
		WScript.Echo "*** Failed to create WBEMScripting.SWBemLocator object*** " & Err.Description
	End If
	Set objWMIService = objSWbemLocator.ConnectServer(strComputer,"root\cimv2", "", "")
	If Err <> 0 Then
		WSCript.Echo "***Failed to get running processes - " & Err.Description
	End If

	Set objFSO=CreateObject("Scripting.FileSystemObject")
	If Right(strOutputFolder,1) <> "\" Then
		strOutputFolder = strOutputFolder & "\"
	End If
	
	outFile= strOutputFolder & strComputer &  "_proc_hash.security"
	Set objFile = objFSO.CreateTextFile(outFile,True)

	Set colProcess = objWMIService.ExecQuery("Select * from Win32_Process")
	For Each objProcess in colProcess
		On Error Resume Next
		currenProcessHash = ""
		If objProcess.ExecutablePath <> "" And Not IsNull(objProcess.ExecutablePath) Then
			currenProcessHash = GetFileHash(objProcess.ExecutablePath)
			currenMTime = objFSO.GetFile(objProcess.ExecutablePath).DateLastModified
			currenATime = objFSO.GetFile(objProcess.ExecutablePath).DateLastAccessed
			currenCTime = objFSO.GetFile(objProcess.ExecutablePath).DateCreated
			currenAttrib = objFSO.GetFile(objProcess.ExecutablePath).Attributes
			currenSize = objFSO.GetFile(objProcess.ExecutablePath).Size
			'Description of the numeric returns for .Attributes:
			'	http://msdn.microsoft.com/en-us/library/5tx15443(v=vs.84).aspx
			objFile.WriteLine strComputer & "	" & Trim(objProcess.ProcessID) & "	" & Trim(objProcess.Name) & "	" & Trim(objProcess.ExecutablePath) & "	" & currenProcessHash & "	" & currenMTime & "	" & currenATime & "	" & currenCTime & "	" & currenAttrib & "	" & currenSize
		End If
	Next
	
	objFile.Close
	On Error GoTo 0
End Function

Function hashLoadedMods(strComputer, strOutputFolder)
	Dim objWMIService, objProcess, colProcess, objSWbemLocator

	'Get all running process through WMI
	Dim illegalList, currenProcessHash
	'WSCript.Echo "Getting all running process for - " & strComputer & " ..."

	Set objSWbemLocator = CreateObject("WbemScripting.SWbemLocator")
	If Err <> 0 Then
		WScript.Echo "*** Failed to create WBEMScripting.SWBemLocator object*** " & Err.Description
	End If
	Set objWMIService = objSWbemLocator.ConnectServer(strComputer,"root\cimv2", "", "")
	If Err <> 0 Then
		WSCript.Echo "***Failed to get running processes - " & Err.Description
	End If

	Set objFSO=CreateObject("Scripting.FileSystemObject")
	If Right(strOutputFolder,1) <> "\" Then
		strOutputFolder = strOutputFolder & "\"
	End If
	
	outFile= strOutputFolder & strComputer &  "_mods_hash.security"
	Set objFile = objFSO.CreateTextFile(outFile,True)

	Set colProcess = objWMIService.ExecQuery("Select * from CIM_ProcessExecutable")
	For Each objProcess in colProcess
		On Error Resume Next
		currenProcessHash = ""
		myMod = Split(objProcess.Antecedent,chr(34))(1)
		myMod = Replace(myMod,(chr(92))&(chr(92)),(chr(92)))
		myPID = Split(objProcess.Dependent,chr(34))(1)
		currenProcessHash = GetFileHash(myMod)
		currenMTime = objFSO.GetFile(myMod).DateLastModified
		currenATime = objFSO.GetFile(myMod).DateLastAccessed
		currenCTime = objFSO.GetFile(myMod).DateCreated
		currenAttrib = objFSO.GetFile(myMod).Attributes
		currenSize = objFSO.GetFile(myMod).Size
		'Description of the numeric returns for .Attributes:
		'	http://msdn.microsoft.com/en-us/library/5tx15443(v=vs.84).aspx
		objFile.WriteLine strComputer & "	" & Trim(myPID) & "	" & Trim(myMod) & "	" & currenProcessHash & "	" & currenMTime & "	" & currenATime & "	" & currenCTime & "	" & currenAttrib & "	" & currenSize
	Next
	On Error GoTo 0
	objFile.Close
End Function

Function GetFileHash(file_name)
	Dim wi, file_hash
	Dim hash_value
	Dim i
	Set wi = CreateObject("WindowsInstaller.Installer")
	Set file_hash = wi.FileHash(file_name, 0)
	hash_value = ""
	For i = 1 To file_hash.FieldCount
	hash_value = hash_value & BigEndianHex(file_hash.IntegerData(i))
	Next
	GetFileHash = hash_value
	Set file_hash = Nothing
	Set wi = Nothing
End Function

Function BigEndianHex(Int)
	Dim result
	Dim b1, b2, b3, b4
	result = right("0000000" & Hex(Int),8)
	b1 = Mid(result, 7, 2)
	b2 = Mid(result, 5, 2)
	b3 = Mid(result, 3, 2)
	b4 = Mid(result, 1, 2)
	BigEndianHex = b1 & b2 & b3 & b4
End Function

Public Function ZipFolder( myFolder, myZipFile )
	' This function recursively ZIPs an entire folder into a single ZIP file,
	' using only Windows' built-in ("native") objects and methods.
	'
	' Last Modified:
	' October 12, 2008
	'
	' Arguments:
	' myFolder   [string]  the fully qualified path of the folder to be ZIPped
	' myZipFile  [string]  the fully qualified path of the target ZIP file
	'
	' Return Code:
	' An array with the error number at index 0, the source at index 1, and
	' the description at index 2. If the error number equals 0, all went well
	' and at index 1 the number of skipped empty subfolders can be found.
	'
	' Notes:
	' [1] If the specified ZIP file exists, it will be overwritten
	'     (NOT APPENDED) without notice!
	' [2] Empty subfolders in the specified source folder will be skipped
	'     without notice; lower level subfolders WILL be added, wether
	'     empty or not.
	'
	' Based on a VBA script (http://www.rondebruin.nl/windowsxpzip.htm)
	' by Ron de Bruin, http://www.rondebruin.nl
	'
	' (Re)written by Rob van der Woude
	' http://www.robvanderwoude.com

		' Standard housekeeping
		Dim intSkipped, intSrcItems
		Dim objApp, objFolder, objFSO, objItem, objTxt
		Dim strSkipped

		Const ForWriting = 2

		intSkipped = 0

		' Make sure the path ends with a backslash
		If Right( myFolder, 1 ) <> "\" Then
			myFolder = myFolder & "\"
		End If

		' Use custom error handling
		On Error Resume Next

		' Create an empty ZIP file
		Set objFSO = CreateObject( "Scripting.FileSystemObject" )
		Set objTxt = objFSO.OpenTextFile( myZipFile, ForWriting, True )
		objTxt.Write "PK" & Chr(5) & Chr(6) & String( 18, Chr(0) )
		objTxt.Close
		Set objTxt = Nothing

		' Abort on errors
		If Err Then
			ZipFolder = Array( Err.Number, Err.Source, Err.Description )
			Err.Clear
			On Error Goto 0
			Exit Function
		End If
		
		' Create a Shell object
		Set objApp = CreateObject( "Shell.Application" )
		
		Dim totalCount
		totalCount = 0
		Const copyType = 20
		' Copy the files to the compressed folder
		For Each objItem in objApp.NameSpace( myFolder ).Items
			If objItem.IsFolder Then
				' Check if the subfolder is empty, and if
				' so, skip it to prevent an error message
			Else
				If InStr(".security", Right(objItem.Name,4)) > 0 Then
					'WScript.Echo objItem.Path & " copying to " & myZipFile
					objApp.NameSpace( myZipFile ).CopyHere objItem, copyType
					totalCount = totalCount + 1
					WScript.Sleep 150
					Do Until objApp.NameSpace( myZipFile ).Items.Count = totalCount
						WScript.Sleep 200
					Loop
				End If
			End If
		Next
				
		Set objFolder = Nothing
		Set objFSO = Nothing

		' Abort on errors
		If Err Then
			ZipFolder = Array( Err.Number, Err.Source, Err.Description )
			Set objApp = Nothing
			Err.Clear
			On Error Goto 0
			Exit Function
		End If

		' Keep script waiting until compression is done
		'Do Until objApp.NameSpace( myZipFile ).Items.Count + intSkipped = totalCount
		'    WScript.Sleep 200
		'Loop
		Set objApp = Nothing

		' Abort on errors
		If Err Then
			ZipFolder = Array( Err.Number, Err.Source, Err.Description )
			Err.Clear
			On Error Goto 0
			Exit Function
		End If

		' Restore default error handling
		On Error Goto 0

		' Return message if empty subfolders were skipped
		If intSkipped = 0 Then
			strSkipped = ""
		Else
			strSkipped = "skipped empty subfolders"
		End If

		' Return code 0 (no error occurred)
		ZipFolder = Array( 0, intSkipped, strSkipped )
End Function
