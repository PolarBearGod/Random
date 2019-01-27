#!/bin/csh
#set -x
onintr quit
set prompt="Press <Return> to continue"
set eyversion=1.6.0
set UNAMEa=`uname -a`
set basedir=/tmp/eyscan
set HOSTNAME=`hostname`
set INDEXF=index.html
#set SYSTEMF=system.out.txt
set SYSTEMF=system.html
#set SPECIFICF=specific.out.txt
set SPECIFICF=specific.html


main:
 while (1)
 clear
  echo "          Please make your selection from the options below: "
  echo ""
  echo "           1) Run the script on this host     "
  echo "           2) Copyright Information           "
  echo "           3) Exit                            "
  echo ""
  echo -n "           Enter Selection: "
   set OUTPUTTYPE=$<

   switch ($OUTPUTTYPE)
   case 1:
        goto systemtype
   case 2:
        goto CopyRight
   case 3:
        exit
   default:
        clear
        echo "Invalid selection"
        echo -n "$prompt"
         tmp=$<
        goto main
  endsw
 end

systemtype:
 clear
  echo "                      Please select the system type:      "
  echo ""
  echo "           1) Linux                           "
  echo "           2) All other Unix flavors          "
  echo "           3) Sybase Database          "   
  echo ""
  echo -n "           Enter Selection: "
   set OUTPUTTYPE=$<

   switch ($OUTPUTTYPE)
   case 1:
        set case=1
        goto systeminfo1
   case 2:
        set case=2
        goto systeminfo2
   case 3:
        set case=3
        goto dbinfo
   default:
        clear
        echo "Invalid selection"
        echo -n "$prompt"
         tmp=$<
        goto systemtype
  endsw
 end


systeminfo1:
  clear
  echo ""
  echo "               Please enter some of the system specifics "
  echo ""
  echo -n "           1) Please enter a unique output folder name : "
   set outfolder = `head -1`
   set outdir = ${basedir}/${outfolder}
  echo -n "           2) What is the Operating System Version?: "
   set version = `head -1`
  echo -n "           3) What is the System Hostname?: "
   set sysname = `head -1`
  echo -n "           4) What is the Administrator's Name?: "
   set adminname = `head -1`
  echo -n "           5) What is the Client's Name?: "
   set clientname = `head -1`
  echo -n "           6) Enter Auditor's Full Name: "
   set auditorname = `head -1`
  echo -n "           7) Enter Server Information / Note To Auditor: "
   set servinfo = `head -1`

  clear
  echo ""
  echo "          System specifics "
  echo "          "
  echo "           1) Output directory: ${outdir}"
  echo "           2) OS Version Number: ${version}"
  echo "           3) System Name: ${sysname}"
  echo "           4) Administrator's Name: ${adminname}"
  echo "           5) Client's Name: ${clientname}"
  echo "           6) Auditor's Full Name: ${auditorname}"
  echo "           7) Server Information / Note To Auditor: ${servinfo}"
  echo ""
  echo -n "           Is the above information correct? [y/n]: "
   set ans=$<
#
if (!(($ans == "y") || ($ans == "Y"))) then
       clear
       goto systeminfo1
       else
       clear
       goto Query
endif

systeminfo2:
  clear
  echo ""
  echo "               Please enter some of the system specifics "
  echo "          "
  echo -n "           1) Please enter a unique output folder name: "
   set outfolder = $<
   set outdir = ${basedir}/${outfolder}
  echo -n "           2) What is the Operating System Version?: "
   set version = $<
  echo -n "           3) What is the System Hostname?: "
   set sysname = $<
  echo -n "           4) What is the Administrator's Name?: "
   set adminname = $<
  echo -n "           5) What is the Client's Name?: "
   set clientname = $<
  echo -n "           6) Enter Auditor's Full Name: "
   set auditorname = $<
  echo -n "           7) Enter Server Information / Note To Auditor: "
   set servinfo = $<

  clear
  echo ""
  echo "          System specifics "
  echo "          "
  echo "           1) Output directory: ${outdir}"
  echo "           2) OS Version Number: ${version}"
  echo "           3) System Name: ${sysname}"
  echo "           4) Administrator's Name: ${adminname}"
  echo "           5) Client's Name: ${clientname}"
  echo "           6) Auditor's Full Name: ${auditorname}"
  echo "           7) Server Information / Note To Auditor: ${servinfo}"
  echo ""
  echo -n "           Is the above information correct? [y/n]: "
   set ans=$<
#
if (!(($ans == "y") || ($ans == "Y"))) then
       clear
       goto systeminfo2
       else
       clear
       goto Query
endif

dbinfo:
  clear
  echo ""
  echo "          Please enter the database connection information "

  echo "          ---------------------------------------------------"
  echo "          Please enter the database connection information "
  echo "                                                          "
  echo "                THIS INFORMATION WILL NOT BE SAVED!             "
  echo ""
  echo -n "           1) Please enter a unique output folder name: "
   set outfolder = `head -1`
   set outdir = ${basedir}/${outfolder}
  echo -n "           2) What is the Database Administrator username?: "
   set admin_name = `head -1`
  echo -n "           3) What is the Database Administrator password?: "
   set admin_pword = `head -1`
  echo -n "           4) What is the Database Name?: "
   set db_name = `head -1`

  clear
  echo ""
  echo "          Database connection information "
  echo "          "
  echo "           1) Output directory: ${outdir}"
  echo "           2) Administrator Name: ${admin_name}"
  echo "           3) Administrator Password: ${admin_pword}"
  echo "           4) Database Name: ${db_name}"
  echo ""
  echo -n "           Is the above information correct? [y/n]: "
   set ans=$<
#
if (!(($ans == "y") || ($ans == "Y"))) then
       clear
       goto dbinfo
       else
       clear
       goto Query
endif

Query:
  echo ""
  echo "            The query script is now running. Please wait..."
  echo ""
  echo ""

sleep 3

#*** Set up output formatting.

#
# This component of the script ensures that the output directory and files are resident on the system  being reviewed.
#

        if (!(-d ${basedir})) then
                mkdir -p ${basedir}
                chmod 700 ${basedir}
                mkdir -p ${outdir}
                chmod 700 ${outdir}
	else
                mkdir -p ${outdir}
                chmod 700 ${outdir}
		    

        endif

                if $case != 3 then
		set INDEXO=${outdir}/${INDEXF}
		set SYSTEMO=${outdir}/${SYSTEMF}
		set SPECIFICO=${outdir}/${SPECIFICF}
		set TEXTO=${outdir}/ey-${HOSTNAME}.txt
                touch ${INDEXO}
                touch ${SPECIFICO}
                touch ${SYSTEMO}
                        # Add new html output files to the list here:
                        echo "<html><head><title>specific.out</title></head><body><h1>Specific to this  flavor of UNIX</h1><pre>" > ${SPECIFICO}
                        echo "<html><head><title>system.out</title></head><body><h1>System  files</h1><pre>" > ${SYSTEMO}
                        echo "<html><head><title>UNIX Script</title></head><body><h1>EY UNIX  Script</h1>" > ${INDEXO}
                        # End of new html output files

                        # System specifics to include on index page
                        #
                        echo "${UNAMEa}<br>" >>& ${INDEXO}
                        echo "<b>OS Version:</b> ${version}<br>">>& ${INDEXO}
                        echo "<b>Adminstrator:</b> ${adminname}<br>">>& ${INDEXO}
                        echo "<b>Client:</b> ${clientname}<br>">>& ${INDEXO}
                        echo "<b>Auditor's Full Name:</b> ${auditorname}<br>">>& ${INDEXO}
                        echo "<b>EY Script Version Number:</b> ${eyversion}<br>">>& ${INDEXO}
                        echo "<b>Server Information / Note To Auditor:</b> ${servinfo}<br><br><ul>">>&  ${INDEXO}
                        echo '<a name=TopOfIndex>' >>& ${INDEXO}
                endif

# Script displays /etc/group file
# 
echo '<a name=Group>' >>& ${SYSTEMO}
echo "Displaying /etc/group" >>& ${SYSTEMO}
echo '*********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/group) then
		cat /etc/group >>& ${SYSTEMO}
	else
		echo "No /etc/group file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO} 

# Script displays /etc/inetd.conf file
# 
echo '<a name=Inetd>' >>& ${SYSTEMO}
echo "Displaying /etc/inetd.conf" >>& ${SYSTEMO}
echo '**************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/inetd.conf) then
		cat /etc/inetd.conf >>& ${SYSTEMO}
	else
		echo "No /etc/inetd.conf file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /etc/passwd file
# 
echo '<a name=DisplayPasswdFile>' >>& ${SYSTEMO}
echo "Displaying /etc/passwd" >>& ${SYSTEMO}
echo '**********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/passwd) then
		cat /etc/passwd >>& ${SYSTEMO}
	else
		echo "No /etc/passwd file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /etc/profile file 
# 
echo '<a name=Profile>' >>& ${SYSTEMO}
echo "Displaying /etc/profile" >>& ${SYSTEMO} 
echo '***********************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
	if ( -f /etc/profile) then 
		cat /etc/profile >>& ${SYSTEMO} 
	else 
		echo "No /etc/profile file found" >>& ${SYSTEMO} 
endif 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /etc/shadow file
# 
echo '<a name=Shadow>' >>& ${SYSTEMO}
echo "Displaying /etc/shadow" >>& ${SYSTEMO}
echo '**********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/shadow) then
		cat /etc/shadow >>& ${SYSTEMO}
	else
		echo "No /etc/shadow file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /var/adm/sulog file 
# 
echo '<a name=Sulog>' >>& ${SYSTEMO}
echo "Displaying /var/adm/sulog" >>& ${SYSTEMO} 
echo '*************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
	if ( -f /var/adm/sulog) then 
		cat /var/adm/sulog >>& ${SYSTEMO} 
	else 
		echo "No /var/adm/sulog file found" >>& ${SYSTEMO} 
endif 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script checks user and group account information 
# 
# Step 1 
echo '<li><a href="specific.html#DataMod">Test Access to Data and Data Modification Utilities</a>' >>& ${INDEXO} 
echo '<a name=DataMod>' >>& ${SPECIFICO} 
echo "<b>Test Access to Data and Data Modification Utilities Step 2</b>" >>& ${SPECIFICO} 
echo "<a href=system.html#DisplayPasswdFile>See '/etc/passwd</a>' file in Section 2" >>& ${SPECIFICO} 
echo '***********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "Displaying >/etc/logingroup file contents" >>& ${SPECIFICO} 
echo '*******************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/cat /etc/logingroup >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "See '<a href=system.html#Group>/etc/group</a>' file in Section 2" >>& ${SPECIFICO} 
echo '**********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

# Script checks access to privelged IT functions 
# 
# Step 1 
echo '<li><a href="specific.html#PrivilegedIT">Test Access to Privileged IT Functions</a>' >>& ${INDEXO} 
echo '<a name=PrivilegedIT>' >>& ${SPECIFICO} 
echo "Displaying >/etc/logingroup file contents" >>& ${SPECIFICO} 
echo '*******************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/cat /etc/logingroup >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "<a href=system.html#DisplayPasswdFile>See '/etc/passwd</a>' file in Section 2" >>& ${SPECIFICO} 
echo '***********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "See '<a href=system.html#Group>/etc/group</a>' file in Section 2" >>& ${SPECIFICO} 
echo '**********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "Displaying /etc/securetty file Permissions" >>& ${SPECIFICO} 
echo '*******************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/cat /etc/securetty >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "<b>Test Access to Privileged IT Functions Step 5</b>" >>& ${SPECIFICO} 
echo "See '<a href=system.html#Sulog>/var/adm/sulog</a>' file in Section 2" >>& ${SPECIFICO} 
echo '**************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

echo "<b>Test Access to Privileged IT Functions Step 7</b>" >>& ${SPECIFICO} 
echo "Displaying System Administration Manager file Permissions" >>& ${SPECIFICO} 
echo '*******************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/ls -al /usr/sbin/sam >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

echo "Displaying System Administration Manager Config file Permissions" >>& ${SPECIFICO} 
echo '*******************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/ls -al /etc/sam/custom/*.cf >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

# Script displays the file permissions of the /etc/passwd and /etc/shadow files 
# 
# Step 1 
echo '<li><a href="specific.html#AccesstoSecurity">Test Access to Security files</a>' >>& ${INDEXO} 
echo '<a name=AccesstoSecurity>' >>& ${SPECIFICO} 
echo "<b>Test Access to Security files Step 1</b>" >>& ${SPECIFICO}
echo "Displaying /etc/passwd Permissions" >>& ${SPECIFICO} 
echo '**********************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
if ( -f /etc/passwd) then 
/usr/bin/ls -l /etc/passwd >>& ${SPECIFICO} 
else 
echo "No /etc/passwd file found" >>& ${SPECIFICO} 
endif 
echo '' >>& ${SPECIFICO} 

# Script displays permissions of the /etc/shadow file 
# 
echo '<a name=DisplayPasswdFileParams>' >>& ${SPECIFICO}
set version = `uname -a | cut -d " " -f 3 | cut -c 3-4,6-` 
set test = 1122
if ( ${version} <= ${test} )then
echo "Displaying shadow password Permissions for HPUX version prior to 11.22" >>& ${SPECIFICO}
if ( -f /tcb/files/auth) then 
/usr/bin/ls -l /tcb/files/auth/[a-z]/ >>& ${SPECIFICO}
else
echo "No files found"
endif 
echo '' >>& ${SPECIFICO}

else

echo "Displaying /etc/shadow Permissions for HPUX version 11.22 or later" >>& ${SPECIFICO} 
echo '**********************' >>& ${SPECIFICO} 
if ( -f /etc/shadow) then 
/usr/bin/ls -l /etc/shadow >>& ${SPECIFICO} 
else 
echo "No /etc/shadow file found" >>& ${SPECIFICO} 
endif
endif
echo '' >>& ${SPECIFICO} 
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

# Script displays the contents of the /etc/passwd and /etc/shadow files 
# 
# Step 1 
echo '<li><a href="specific.html#DefaultAccounts">Test Default Accounts & Passwords</a>' >>& ${INDEXO} 
echo '<a name=DefaultAccounts>' >>& ${SPECIFICO} 
echo "<b>Test Default Accounts & Passwords Step 1</b>" >>& ${SPECIFICO}
echo "See '<a href=system.html#DisplayPasswdFile>/etc/passwd</a>' in Section 2" >>& ${SPECIFICO} 
echo '*******************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

set version = `uname -a | cut -d " " -f 3 | cut -c 3-4,6-` 
set test = 1122
if ( ${version} <= ${test} ) then
echo "For HPUX versions prior to 11.22 refer to the following output" >>& ${SPECIFICO} 
/usr/bin/find /tcb/files/auth/ -name '*' ?exec cat {} \;    >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

else

echo "For HPUX versions 11.22 or later, see '<a href=system.html#Shadow>/etc/shadow</a>' in Section 2" >>& ${SPECIFICO} 
echo '*******************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}
endif

echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

# Script displays file permissions and contents of /etc/hosts.equiv 
# 
# Test For Trust Relationships Step 1 
# 
echo '<li><a href="specific.html#TrustRelationships">Test For Trust Relationships</a>' >>& ${INDEXO} 
echo '<a name=TrustRelationships>' >>& ${SPECIFICO} 
echo "<b>Test For Trust Relationships Step 1</b>" >>& ${SPECIFICO} 
echo "Displaying permissions and contents of /etc/hosts.equiv" >>& ${SPECIFICO} 
echo '**********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
if ( -f /etc/hosts.equiv ) then 
ls -l /etc/hosts.equiv >>& ${SPECIFICO} 
cat /etc/hosts.equiv >>& ${SPECIFICO} 
else 
echo "No /etc/hosts.equiv file found" >>& ${SPECIFICO} 
endif 
echo '' >>& ${SPECIFICO} 

echo "Test For Trust Relationships Step 4" >>& ${SPECIFICO} 
echo "Listing .rhost files" >>& ${SPECIFICO} 
echo '**********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
/usr/bin/find / -name '.rhosts' -exec /bin/ls -al {} \; -exec /bin/cat {} \; >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO} 
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

# Script displays the contents of the /etc/passwd and /etc/shadow files 
# 
# Step 1 
echo '<li><a href="specific.html#ShadowPassword">Test for Use of Shadow Password file</a>' >>& ${INDEXO} 
echo '<a name=ShadowPassword>' >>& ${SPECIFICO} 
echo "<b>Test for Use of Shadow Password File Step 1</b>" >>& ${SPECIFICO} 
echo "See '<a href=system.html#DisplayPasswdFile>'/etc/passwd</a>' file in Section 2" >>& ${SPECIFICO} 
echo '***********************************' >>& ${SPECIFICO} 

echo "Default Accounts Step 1" >>& ${SPECIFICO}
set version = `uname -a | cut -d " " -f 3 | cut -c 3-4,6-` 
set test = 1122
if ( ${version} <= ${test} ) then
echo "For HPUX versions prior to 11.22 refer to the following output"
/usr/bin/find /tcb/files/auth/ -name '*' ?exec cat {} \;    >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

else
 
echo "For HPUX versions 11.22 or later, see '<a href=system.html#SecurityPasswd>/etc/shadow</a>' file in Section 2" >>& ${SPECIFICO} 
echo '********************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

endif
  
echo '' >>& ${SPECIFICO} 
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}


# Script displays the contents of the /etc/ftpusers file 
# Step 1 
echo '<li><a href="specific.html#DisplayFtpusersFile">Test FTP Access</a>' >>& ${INDEXO}  
echo '<a name=DisplayFtpusersFile>' >>& ${SPECIFICO} 
echo "<b>Test FTP Access Step 1</b>" >>& ${SPECIFICO} 
echo "Displaying /etc/ftpusers file contents" >>& ${SPECIFICO} 
echo '**********************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
if ( -f /etc/ftpd/ftpusers) then 
/usr/bin/cat /etc/ftpd/ftpusers >>& ${SPECIFICO} 
else 
echo "No /etc/ftpd/ftpusers file found" >>& ${SPECIFICO} 
endif 
echo '' >>& ${SPECIFICO} 

echo "<a href=system.html#DisplayPasswdFile>See '/etc/passwd</a>' file in Section 2" >>& ${SPECIFICO} 
echo '***********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

# Script checks Password Settings 
# 
# Step 1 
echo '<li><a href="specific.html#PasswordSettings">Test Password Settings</a>' >>& ${INDEXO} 
echo '<a name=PasswordSettings>' >>& ${SPECIFICO} 
echo "<b>Test Password Settings Step 1</b>" >>& ${SPECIFICO} 
echo "Displaying /tcb/files/auth/system/default contents" >>& ${SPECIFICO} 
echo '**********************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 
if ( -f /tcb/files/auth/system/default) then 
/usr/bin/cat /tcb/files/auth/system/default >>& ${SPECIFICO} 
else 
echo "No /tcb/files/auth/system/default file found" >>& ${SPECIFICO} 
endif 
echo '' >>& ${SPECIFICO} 

echo "Default Umask Value Step 1" >>& ${SPECIFICO} 
echo "See '<a href=system.html#Profile>/etc/profile</a>' file in Section 2" >>& ${SPECIFICO} 
echo '************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 


set version = `uname -a | cut -d " " -f 3 | cut -c 3-4,6-` 
set test = 1122
if ( ${version} <= ${test} ) then
 # Script displays permissions of the /etc/shadow file 
 # 
 echo '<a name=ShadowFileCont>' >>& ${SPECIFICO} 
 echo "Displaying shadow password files for HPUX version prior to 11.22" >>& ${SPECIFICO}
 if ( -d /tcb/files/auth) then 
  /usr/bin/cat /tcb/files/auth/[a-z]/* >>& ${SPECIFICO} 
 else 
 echo "No /tcb/files/auth/ directory found" >>& ${SPECIFICO} 
 endif
 endif
else

 # Script displays permissions of the /etc/shadow file 
 # 
 echo '<a name=ShadowFileCont>' >>& ${SPECIFICO} 
 echo "Displaying /etc/shadow file for HPUX version 11.22 or later" >>& ${SPECIFICO} 
 echo '**********************' >>& ${SPECIFICO} 
 echo '' >>& ${SPECIFICO} 
 if ( -f /etc/shadow) then 
 /usr/bin/ls -l /etc/shadow >>& ${SPECIFICO} 
 else 
 echo "No /etc/shadow file found" >>& ${SPECIFICO} 
 endif 
endif
echo '' >>& ${SPECIFICO}


echo "Displaying shadow password Permissions for HPUX version prior to 11.22" >>& ${SPECIFICO}
if ( -d /tcb/files/auth) then 
/usr/bin/ls ?l  /tcb/files/auth/[a-z]/* >>& ${SPECIFICO}
else 
 echo "No /tcb/files/auth file found" >>& ${SPECIFICO} 
 endif  
echo '' >>& ${SPECIFICO}

echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

#################################################################
#
# This portion should remain at the bottom of this script
#
################################################################

# Output file

if $case == 3 then
        mv EY_SybaseDBDump.html /${outdir}
        goto cleanup
else

cat ${INDEXO}  >>& ${TEXTO}
echo "*****************************" >>& ${TEXTO}
echo "-----------------------------" >>& ${TEXTO}
echo "SECTION 1: SPECIFIC WORKSTEPS" >>& ${TEXTO}
echo "-----------------------------" >>& ${TEXTO}
echo "*****************************" >>& ${TEXTO}
echo '' >>& ${TEXTO}
cat ${SPECIFICO} >>& ${TEXTO}
echo "******************************" >>& ${TEXTO}
echo "------------------------------" >>& ${TEXTO}
echo "SECTION 2: COMMON SYSTEM FILES" >>& ${TEXTO}
echo "------------------------------" >>& ${TEXTO}
echo "******************************" >>& ${TEXTO}
echo '' >>& ${TEXTO}
cat ${SYSTEMO} >>& ${TEXTO}

cleanup:

sleep 3
 clear
  echo ""
  echo "          All finished.  What's next?"
  echo ""
  echo "           1) Exit"
  echo "           2) Copyright Information"
  echo -n "           Enter Selection: "
   set CLEANUPTYPE=$<

   switch ($CLEANUPTYPE)
   case 1:
        goto quit
   case 2:
        goto CopyRight2
   default:
        clear
        echo "Invalid selection"
        echo -n "$prompt"
        set tmp=$<
        goto cleanup
  endsw


quit:
 clear
 echo ""
 echo "          Report File is located in:"
 echo "          '${outdir}'"
 echo ""
 echo "          Thanks for your cooperation"
 echo ""
 echo ""
exit 1
