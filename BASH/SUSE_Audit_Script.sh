#!/bin/csh
#set -x
onintr quit
set prompt="Press <Return> to continue"
set version=1.6.0
set UNAMEa=`uname -a`
set basedir=/tmp/scan
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

CopyRight:
  clear
  echo ""
  echo "          ---------------------------------------------------"
  echo " This script is privileged and/or confidential, and the developers do not"
  echo " waive any related rights.  Any distribution, use, or copying of this"
  echo " script or the information it contains by other than the intended"
  echo " user is unauthorized."
  echo " "
    echo "          ---------------------------------------------------"
sleep 5
goto main

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
		set TEXTO=${outdir}/${HOSTNAME}.txt
                touch ${INDEXO}
                touch ${SPECIFICO}
                touch ${SYSTEMO}
                        # Add new html output files to the list here:
                        echo "<html><head><title>specific.out</title></head><body><h1>Specific to this  flavor of UNIX</h1><pre>" > ${SPECIFICO}
                        echo "<html><head><title>system.out</title></head><body><h1>System  files</h1><pre>" > ${SYSTEMO}
                        echo "<html><head><title>UNIX Script</title></head><body><h1> UNIX  Script</h1>" > ${INDEXO}
                        # End of new html output files

                        # System specifics to include on index page
                        #
                        echo "${UNAMEa}<br>" >>& ${INDEXO}
                        echo "<b>OS Version:</b> ${version}<br>">>& ${INDEXO}
                        echo "<b>Adminstrator:</b> ${adminname}<br>">>& ${INDEXO}
                        echo "<b>Client:</b> ${clientname}<br>">>& ${INDEXO}
                        echo "<b>Auditor's Full Name:</b> ${auditorname}<br>">>& ${INDEXO}
                        echo "<b>Script Version Number:</b> ${version}<br>">>& ${INDEXO}
                        echo "<b>Server Information / Note To Auditor:</b> ${servinfo}<br><br><ul>">>&  ${INDEXO}
                        echo '<a name=TopOfIndex>' >>& ${INDEXO}
                endif

# Script finds and displays unauthorized device files
# 
echo '<a name=DeviceFiles>' >>& ${SYSTEMO}
echo "Displaying all device files" >>& ${SYSTEMO} 
echo '************************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
find / \( -fstype nfs -prune \) -o \( -type c -o -type b \) -exec ls -al {} \; >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script shows all executable files
# 
echo '<a name=ExecutableFiles>' >>& ${SYSTEMO}
echo "Displaying executable files" >>& ${SYSTEMO}
echo '***************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	find / \( -fstype nfs -prune \) -o -type f \( -perm -100 -o -perm -010 -o -perm -001 \) -exec ls -al {} \; >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays existence of SUID and SGID files
#
echo '<a name=SUID>' >>& ${SYSTEMO}
echo "Displaying SUID files" >>& ${SYSTEMO}
echo '*********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	find / \( -fstype nfs -prune \) -o -type f -perm -4000 -exec ls -dal {} \; >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

echo "Displaying SGID files" >>& ${SYSTEMO}
echo '*********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	find / \( -fstype nfs -prune \) -o -type f -perm -2000 -exec ls -dal {} \; >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO} 

# Script displays files that are both world-writable and executable
#
echo '<a name=WorldWriteableFiles>' >>& ${SYSTEMO}
echo "Displaying files that are both world-writeable and executable" >>&  ${SYSTEMO}
echo '*************************************************************' >>&  ${SYSTEMO}
echo '' >>&  ${SYSTEMO}
  find / \( -fstype nfs -prune \) -o -type f -perm -00003 -exec ls -al {} \; >>&  ${SYSTEMO}
echo '' >>&  ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO} 

# Script displays all world writable directories
#
echo '<a name=WorldWriteableDirs>' >>& ${SYSTEMO}
echo "Displaying world writable directories" >>& ${SYSTEMO} 
echo '*************************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
find / \( -fstype nfs -prune \) -o -type d -perm -2 -exec ls -dlL {} \; >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}


# Script displays file permissions of /dev 
# 
echo '<a name=PermissionsDev>' >>& ${SYSTEMO}
echo "Displaying file permissions of /dev" >>& ${SYSTEMO} 
echo '***********************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
	if ( -d /dev) then 
		ls -al /dev >>& ${SYSTEMO} 
	else 
		echo "No /dev directory found" >>& ${SYSTEMO} 
endif 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

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

# Script shows user account information
# 
echo '<a name=LoginDefs>' >>& ${SYSTEMO}
echo "Displaying /etc/login.defs" >>& ${SYSTEMO}
echo '**************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
  cat /etc/login.defs >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Displays sendmail configuration info
#
echo '<a name=SendmailConf>' >>& ${SYSTEMO}
echo "Displaying /etc/mail/sendmail.cf" >>& ${SYSTEMO}
echo '********************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
if ( -f /etc/mail/sendmail.cf ) then
	cat /etc/mail/sendmail.cf >>& ${SYSTEMO}
else
	echo "No /etc/mail/sendmail.cf file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /etc/named.conf file
# 
echo '<a name=NamedConf>' >>& ${SYSTEMO}
echo "Displaying /etc/named.conf" >>& ${SYSTEMO}
echo '**************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/named.conf) then
		cat /etc/named.conf >>& ${SYSTEMO}
	else
		echo "No /etc/named.conf file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO} 

# Displays OpenLDAP network communication information
#
echo '<a name=OpenLDAP>' >>& ${SYSTEMO}
echo "Displaying /etc/openldap/slapd.conf" >>& ${SYSTEMO}
echo '************************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
  cat /etc/openldap/slapd.conf >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /etc/pam.d/system-auth file
#
echo '<a name=PamdSys>' >>& ${SYSTEMO}
echo "Displaying etc/pam.d/system-auth" >>& ${SYSTEMO}
echo '********************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
if ( -f /etc/pam.d/system-auth ) then
	cat /etc/pam.d/system-auth >>& ${SYSTEMO}
else
	echo "No /etc/pam.d/system-auth file found" >>& ${SYSTEMO}
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

# Script checks for services
# 
echo '<a name=ChkConfig>' >>& ${SYSTEMO}
echo "Displaying /sbin/chkconfig --list" >>& ${SYSTEMO} 
echo '*********************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
	/sbin/chkconfig --list >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}  

# Script displays ypcat passwd file
# 
echo '<a name=Ypcat>' >>& ${SYSTEMO}
echo "Displaying ypcat passwd" >>& ${SYSTEMO}
echo '***********************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	ypcat passwd >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}

# Script displays /var/log/secure file 
# 
echo '<a name=Secure>' >>& ${SYSTEMO}
echo "Displaying /var/log/secure" >>& ${SYSTEMO} 
echo '**************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO} 
if ( -f /var/log/secure) then 
cat /var/log/secure >>& ${SYSTEMO} 
else 
echo "No /var/log/secure file found" >>& ${SYSTEMO} 
endif 
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO} 

# Script finds all executable files and shows group permissions 
# 
# Access to Administration Tools and System Utilities Step 1
#
echo '<li><a href=specific.html#AdminTools2>Access to Administration Tools and System Utilities</a>' >>& ${INDEXO}
echo '<a name=AdminTools2>' >>& ${SPECIFICO}
echo "Access to Administration Tools and System Utilities Step 1" >>& ${SPECIFICO}
echo "See '<a href=system.html#ExecutableFiles>executable</a>' files in Section 2" >>& ${SPECIFICO}
echo '***********************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Access to Administration Tools and System Utilities Step 3
#
echo "Access to Administration Tools and System Utilities Step 3" >>& ${SPECIFICO}
echo "See '<a href=system.html#Group>/etc/group</a>' file in Section 2" >>& ${SPECIFICO}
echo '**********************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO} 

# Script checks for FTP service
# 
# Access to the FTP Service Step 1
#
echo '<li><a href=specific.html#FtpService>Access to the FTP Service</a>' >>& ${INDEXO}
echo '<a name=FtpService>' >>& ${SPECIFICO}
echo "Access to the FTP Service Step 1" >>& ${SPECIFICO}
echo "See '<a href=system.html#ChkConfig>chkconfig --list</a>' in Section 2" >>& ${SPECIFICO}
echo '***********************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Access to the FTP Service Step 2
#
echo "Access to the FTP Service Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Vsftpd>vsftpd.ftpusers</a>' in Section 2" >>& ${SPECIFICO}
echo '********************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Access to the FTP Service Step 2
#
echo "Access to the FTP Service Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Vsftpd>/ftpaccess</a>' in Section 2" >>& ${SPECIFICO}
echo '**************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Access to the FTP Service Step 2
#
echo "Access to the FTP Service Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Ftpusers>/ftpusers</a>' file in Section 2" >>& ${SPECIFICO}
echo '*************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO} 

# Script checks for FTP service
# 
# Anonymous Login to FTP Step 1
#
echo '<li><a href=specific.html#AnonymousLoginFTP2>Anonymous Login to FTP</a>' >>& ${INDEXO}
echo '<a name=AnonymousLoginFTP2>' >>& ${SPECIFICO}
echo "Anonymous Login to FTP Step 1" >>& ${SPECIFICO}
echo "See '<a href=system.html#ChkConfig>chkconfig --list</a>' in Section 2" >>& ${SPECIFICO}
echo '**********************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Anonymous Login to FTP Step 2
#
echo "Anonymous Login to FTP Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Vsftpd>vsftpd.ftpusers</a>' in Section 2" >>& ${SPECIFICO} 
echo '********************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Anonymous Login to FTP Step 2
#
echo "Anonymous Login to FTP Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Vsftpd>/ftpaccess</a>' in Section 2" >>& ${SPECIFICO}
echo '**************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Anonymous Login to FTP Step 2
#
echo "Anonymous Login to FTP Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#Ftpusers>/ftpusers</a>' file in Section 2" >>& ${SPECIFICO} 
echo '*************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

# Script checks permissions to the C compilers
# 
# C Compiler Step 1
#
echo '<li><a href=specific.html#CCompiler>C Compiler</a>' >>& ${INDEXO}
echo '<a name=CCompiler>' >>& ${SPECIFICO}
echo "C Compiler Step 1" >>& ${SPECIFICO}
echo "Displaying permissions of /usr/bin/gcc" >>& ${SPECIFICO}
echo '**************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
if ( -f /usr/bin/gcc ) then
	ls -al /usr/bin/gcc >>& ${SPECIFICO}
else
	echo "No /usr/bin/gcc file found" >>& ${SPECIFICO}
endif
echo '' >>& ${SPECIFICO}

# C Compiler Step 1
#
echo "C Compiler Step 1" >>& ${SPECIFICO}
echo "Displaying permissions of /usr/bin/cc" >>& ${SPECIFICO}
echo '*************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
if ( -f /usr/bin/cc ) then
	ls -al /usr/bin/cc >>& ${SPECIFICO}
else
	echo "No /usr/bin/cc" >>& ${SPECIFICO}
endif
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO} 

# Displays account access
#
# Command Line Access Step 1
#
echo '<li><a href=specific.html#CommandLineAccess12>Command Line Access</a>' >>& ${INDEXO}
echo '<a name=CommandLineAccess2>' >>& ${SPECIFICO}
echo "Command Line Access Step 1" >>& ${SPECIFICO}
echo "See '<a href=system.html#DisplayPasswdFile>/etc/passwd</a>' file in Section 2" >>& ${SPECIFICO}
echo '***********************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Command Line Access Step 2
#
echo "Command Line Access Step 2" >>& ${SPECIFICO}
echo "Displaying shell files for bash users" >>& ${SPECIFICO}
echo '*************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
  find /home \( -fstype nfs -prune \) -o \( -name .bash_profile -o -name .bashrc \) -print -exec ls -al {} \; -exec cat {} \; >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Command Line Access Step 3
#
echo "Command Line Access Step 3" >>& ${SPECIFICO}
echo "Displaying shell files for korn, shell, bourne, and trusted users" >>& ${SPECIFICO}
echo '*****************************************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
  find /home \( -fstype nfs -prune \) -o -name .profile -print -exec ls -al {} \; -exec cat {} \; >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Command Line Access Step 4
#
echo "Command Line Access Step 4" >>& ${SPECIFICO}
echo "Displaying shell files for c-shell users" >>& ${SPECIFICO}
echo '****************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
  find /home \( -fstype nfs -prune \) -o \( -name .cshrc -o -name .login -o -name .logout \) -print -exec ls -al {} \; -exec cat {} \; >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# Command Line Access Step 5
#
echo "Command Line Access Step 5" >>& ${SPECIFICO} 
echo "See '<a href=system.html#Vsftpd>vsftpd.ftpusers</a>' in Section 2" >>& ${SPECIFICO} 
echo '********************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

# Command Line Access Step 5 
# 
echo "Command Line Access Step 5" >>& ${SPECIFICO} 
echo "See '<a href=system.html#Vsftpd>/ftpaccess</a>' in Section 2" >>& ${SPECIFICO}
echo '**************************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO} 

# Command Line Access Step 5 
# 
echo "Command Line Access Step 5" >>& ${SPECIFICO} 
echo "See '<a href=system.html#Ftpusers>/ftpusers</a>' file in Section 2" >>& ${SPECIFICO}
echo '*********************************' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO} 
echo '' >>& ${SPECIFICO}

# Script displays ftp configuration files
#
echo '<a name=Vsftpd>' >>& ${SYSTEMO}
echo "Displaying /etc/vsftpd.ftpusers" >>& ${SYSTEMO}
echo '*******************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
if ( -f /etc/vsftpd.ftpusers ) then
	cat /etc/vsftpd.ftpusers >>& ${SYSTEMO}
else
	echo "No /etc/vsftpd.ftpusers file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}


# Script shows file permissions
#
# File Permissions Step 1
#
echo '<li><a href=specific.html#FilePermissions3>File Permissions</a>' >>& ${INDEXO}
echo '<a name=FilePermissions3>' >>& ${SPECIFICO}
echo "File Permissions Step 1" >>& ${SPECIFICO}
echo "Displaying root path variable" >>& ${SPECIFICO}
echo '*****************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
  /bin/echo $PATH >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# File Permissions Step 2
#
echo "File Permissions Step 2" >>& ${SPECIFICO}
echo "See '<a href=system.html#WorldWriteableDirs>world writable directories</a>' in Section 2" >>& ${SPECIFICO}
echo '*********************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}

# File Permissions Step 4
#
echo "File Permissions Step 4" >>& ${SPECIFICO}
echo "See '<a href=system.html#WorldWriteableFiles>world writable and executable</a>' files in Section 2" >>& ${SPECIFICO}
echo '******************************************************' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SPECIFICO}
echo '' >>& ${SPECIFICO}


# Script displays /etc/ftpusers file
#
echo '<a name=Ftpusers>' >>& ${SYSTEMO}
echo "Displaying contents of /etc/ftpusers" >>& ${SYSTEMO}
echo '********************************' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}
	if ( -f /etc/ftpusers) then
                cat /etc/ftpusers >>& ${SYSTEMO}
	else
                echo "No /etc/ftpusers file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}


# Script displays vsftpd.conf file
# 
echo '<a name=VsftpdConf>' >>& ${SYSTEMO}
echo "Displaying /etc/vsftpd.conf" >>& ${SYSTEMO} 
echo '************************************' >>& ${SYSTEMO} 
echo '' >>& ${SYSTEMO}
	if ( -f /etc/vsftpd.conf) then
		cat /etc/vsftpd.conf >>& ${SYSTEMO}
	else
		echo "No /etc/vsftpd.conf file found" >>& ${SYSTEMO}
endif
echo '' >>& ${SYSTEMO}
echo '<a href=index.html#TopOfIndex>Return to Report</a>' >>& ${SYSTEMO}
echo '' >>& ${SYSTEMO}


#################################################################
#
# This portion should remain at the bottom of this script
#
################################################################

# Output file

if $case == 3 then
        mv SybaseDBDump.html /${outdir}
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
