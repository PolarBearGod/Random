set echo on
REM **************************************************************************
REM UNIX Audit Script
REM **************************************************************************

set echo off
set termout on
set heading on
set feedback off
set trimspool on
set linesize 200
set pagesize 200
set markup html on spool on

Spool OracleDBDump.html

prompt [Control]: Log Failed Connections - Oracle 11g
prompt [Control]: Test Password Settings - Oracle 11g
prompt [Query] : SELECT USER_NAME,FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='CREATE SESSION';
SELECT USER_NAME,FAILURE FROM DBA_STMT_AUDIT_OPTS WHERE AUDIT_OPTION='CREATE SESSION';

prompt [Control]: Developer Roles - Oracle 11g
prompt [Control]: Remote Application Accounts - Oracle 11g
prompt [Control]: Role-based Privileges: Administrator - Oracle 11g
prompt [Control]: Role-based Privileges: Auditing - Oracle 11g
prompt [Control]: Role-based Privileges: DBA - Oracle 11g
prompt [Control]: Role-based Privileges: Help Desk - Oracle 11g
prompt [Control]: Role-based Privileges: Operator - Oracle 11g
prompt [Control]: Role-based Privileges: Process - Oracle 11g
prompt [Control]: Role-based Privileges: Security Administration - Oracle 11g
prompt [Control]: Test Access to Privileged IT Functions - Oracle 11g
prompt [Control]: Test Access to Production Data - Oracle 11g
prompt [Control]: Test for Access Assigned to PUBLIC Role - Oracle 11g
prompt [Control]: Test Logical Access Segregation of Duties - Oracle 11g
prompt [Query] : SELECT * FROM DBA_ROLE_PRIVS;
SELECT * FROM DBA_ROLE_PRIVS;

prompt [Control]: Test Access to Privileged IT Functions - Oracle 11g
prompt [Control]: Test for Access Assigned to PUBLIC Role - Oracle 11g
prompt [Control]: Test Logical Access Segregation of Duties - Oracle 11g
prompt [Query] : SELECT * FROM DBA_SYS_PRIVS
prompt WHERE 
prompt  PRIVILEGE='CREATE USER' OR
prompt  PRIVILEGE='BECOME USER' OR
prompt  PRIVILEGE='ALTER USER' OR
prompt  PRIVILEGE='DROP USER' OR
prompt  PRIVILEGE='CREATE ROLE' OR
prompt  PRIVILEGE='ALTER ANY ROLE' OR
prompt  PRIVILEGE='DROP ANY ROLE' OR
prompt  PRIVILEGE='GRANT ANY ROLE' OR
prompt  PRIVILEGE='CREATE PROFILE' OR
prompt  PRIVILEGE='ALTER PROFILE' OR
prompt  PRIVILEGE='DROP PROFILE' OR
prompt  PRIVILEGE='CREATE ANY TABLE' OR
prompt  PRIVILEGE='ALTER ANY TABLE' OR
prompt  PRIVILEGE='DROP ANY TABLE' OR
prompt  PRIVILEGE='INSERT ANY TABLE' OR
prompt  PRIVILEGE='UPDATE ANY TABLE' OR
prompt  PRIVILEGE='DELETE ANY TABLE' OR
prompt  PRIVILEGE='CREATE ANY PROCEDURE' OR
prompt  PRIVILEGE='ALTER ANY PROCEDURE' OR
prompt  PRIVILEGE='DROP ANY PROCEDURE' OR
prompt  PRIVILEGE='CREATE ANY TRIGGER' OR
prompt  PRIVILEGE='ALTER ANY TRIGGER' OR
prompt  PRIVILEGE='DROP ANY TRIGGER' OR
prompt  PRIVILEGE='CREATE TABLESPACE' OR
prompt  PRIVILEGE='ALTER TABLESPACE' OR
prompt  PRIVILEGE='DROP TABLESPACES' OR
prompt  PRIVILEGE='ALTER DATABASE' OR
prompt  PRIVILEGE='ALTER SYSTEM';
SELECT * FROM DBA_SYS_PRIVS
WHERE 
 PRIVILEGE='CREATE USER' OR
 PRIVILEGE='BECOME USER' OR
 PRIVILEGE='ALTER USER' OR
 PRIVILEGE='DROP USER' OR
 PRIVILEGE='CREATE ROLE' OR
 PRIVILEGE='ALTER ANY ROLE' OR
 PRIVILEGE='DROP ANY ROLE' OR
 PRIVILEGE='GRANT ANY ROLE' OR
 PRIVILEGE='CREATE PROFILE' OR
 PRIVILEGE='ALTER PROFILE' OR
 PRIVILEGE='DROP PROFILE' OR
 PRIVILEGE='CREATE ANY TABLE' OR
 PRIVILEGE='ALTER ANY TABLE' OR
 PRIVILEGE='DROP ANY TABLE' OR
 PRIVILEGE='INSERT ANY TABLE' OR
 PRIVILEGE='UPDATE ANY TABLE' OR
 PRIVILEGE='DELETE ANY TABLE' OR
 PRIVILEGE='CREATE ANY PROCEDURE' OR
 PRIVILEGE='ALTER ANY PROCEDURE' OR
 PRIVILEGE='DROP ANY PROCEDURE' OR
 PRIVILEGE='CREATE ANY TRIGGER' OR
 PRIVILEGE='ALTER ANY TRIGGER' OR
 PRIVILEGE='DROP ANY TRIGGER' OR
 PRIVILEGE='CREATE TABLESPACE' OR
 PRIVILEGE='ALTER TABLESPACE' OR
 PRIVILEGE='DROP TABLESPACES' OR
 PRIVILEGE='ALTER DATABASE' OR
 PRIVILEGE='ALTER SYSTEM';


prompt [Control]: Guest Accounts - Oracle 11g
prompt [Control]: Intelligent Agent - Oracle 11g
prompt [Control]: Log Application Account Activity - Oracle 11g
prompt [Control]: Network Traffic Encryption - Oracle 11g
prompt [Control]: Passwords for Database Administration Accounts - Oracle 11g
prompt [Control]: Privileged Account Review - Oracle 11g
prompt [Control]: Test Access to Privileged IT Functions - Oracle 11g
prompt [Control]: Test Access to Production Data - Oracle 11g
prompt [Control]: Test for Global and Enterprise Roles - Oracle 11g
prompt [Control]: Test for Host-Based Authentication Methods - Oracle 11g
prompt [Control]: Test Logical Access Segregation of Duties - Oracle 11g
prompt [Control]: Test New User Setup - Oracle 11g
prompt [Control]: Test Password Settings - Oracle 11g
prompt [Control]: Unique IDs - Oracle 11g
prompt [Control]: User ID Naming Convention - Oracle 11g
prompt [Query] : SELECT * FROM DBA_USERS;
SELECT * FROM DBA_USERS;

prompt [Control]: Test Access to Production Data - Oracle 11g
prompt [Query] : SELECT * FROM DBA_TAB_PRIVS  WHERE GRANTABLE = 'YES';
SELECT * FROM DBA_TAB_PRIVS  WHERE GRANTABLE = 'YES';

prompt [Control]: Test Default Accounts and Passwords - Oracle 11g
prompt [Query] : SELECT * FROM DBA_USERS_WITH_DEFPWD;
SELECT * FROM DBA_USERS_WITH_DEFPWD;

prompt [Control]: Test for Host-Based Authentication Methods - Oracle 11g
prompt [Query] : SELECT * FROM V$PARAMETER2 WHERE NAME in ('remote_os_authent','os_authent_prefix');
SELECT * FROM V$PARAMETER2 WHERE NAME in ('remote_os_authent','os_authent_prefix');

prompt [Control]: Test Password Settings - Oracle 11g
prompt [Query] : SELECT NAME,TEXT FROM DBA_SOURCE WHERE NAME in (SELECT LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME ='PASSWORD_VERIFY_FUNCTION') ORDER BY NAME,LINE;
SELECT NAME,TEXT FROM DBA_SOURCE WHERE NAME in (SELECT LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME ='PASSWORD_VERIFY_FUNCTION') ORDER BY NAME,LINE;

prompt [Control]: Test Access to Production Data - Oracle 11g
prompt [Control]: Test for Access Assigned to PUBLIC Role - Oracle 11g
prompt [Query] : SELECT UNIQUE GRANTEE, TABLE_NAME FROM DBA_TAB_PRIVS
prompt WHERE
prompt  (PRIVILEGE='INSERT' OR
prompt  PRIVILEGE='UPDATE' OR
prompt  PRIVILEGE='ALTER' OR
prompt  PRIVILEGE='DELETE' OR
prompt  PRIVILEGE='EXECUTE');
SELECT UNIQUE GRANTEE, TABLE_NAME FROM DBA_TAB_PRIVS
WHERE
 (PRIVILEGE='INSERT' OR
 PRIVILEGE='UPDATE' OR
 PRIVILEGE='ALTER' OR
 PRIVILEGE='DELETE' OR
 PRIVILEGE='EXECUTE');

prompt [Control]: Restrict Ability To Connect - Oracle 11g
prompt [Control]: Test Access to Privileged IT Functions - Oracle 11g
prompt [Query] : SELECT * FROM V$PWFILE_USERS;
SELECT * FROM V$PWFILE_USERS;

prompt end of script
spool off
set markup html off

