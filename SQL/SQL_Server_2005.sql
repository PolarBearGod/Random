/* Control: Test Account Lockout - SQL Server 2005*/
/* Control: Test Password Composition - SQL Server 2005*/
/* Control: Test Password Expiration - SQL Server 2005*/
/* Control: Test Password History - SQL Server 2005*/

print '==============================================================================='
print 'List of SQL user logins and password policy'
print 'Control: Test Account Lockout - SQL Server 2005' 
print 'Control: Test Password Composition - SQL Server 2005'
print 'Control: Test Password Expiration - SQL Server 2005'
print 'Control: Test Password History - SQL Server 2005'
go
SELECT * FROM sys.sql_logins
go

/* Control: Test Default Accounts & Passwords - SQL Server 2005*/
/* Control: Test User Validation Procedures - SQL Server 2005*/
/* Control: Test New User Setup - SQL Server 2005*/
/* control: Unique IDs - SQL Server 2005*/

print '==============================================================================='
print 'General system security settings'
print 'Control: Test Default Accounts & Passwords - SQL Server 2005'
print 'Control: Test User Validation Procedures - SQL Server 2005'
print 'Control: Test New User Setup - SQL Server 2005'
print 'Control: Unique IDs - SQL Server 2005'
go
SELECT * FROM sys.sql_logins
go

/* Control: Access Control - SQL Server 2005 */
/* Control: Stored Procedures - SQL Server 2005*/
/* Control: Guest Accounts - SQL Server 2005*/
/* Control: Promote User Permissions - SQL Server 2005*/
/* Control: Job Scheduling Function - SQL Server 2005*/
/* Control: Review User Object Access Privileges - SQL Server 2005*/
/* Control: Test Access to Production Data - SQL Server 2005*/
/* Control: Role-based Privileges: End Users - SQL Server 2005*/
/* Control: Permission on Web Tasks Table - SQL Server 2005*/
/* Control: Production Support Role - SQL Server 2005*/

print '==============================================================================='
print 'Stored procedure: SP_HELPROTECT'
print 'Control: Access Controls - SQL Server 2005'
print 'Control: Stored Procedures - SQL Server 2005'
print 'Control: Guest Accounts - SQL Server 2005'
print 'Control: Promote User Permissions - SQL Server 2005'
print 'Control: Job Scheduling Function - SQL Server 2005'
print 'Control: Review User Object Access Privileges - SQL Server 2005'
print 'control: Test Access to Production Data - SQL Server 2005'
print 'Control: Role-based Privileges: End Users - SQL Server 2005'
print 'Control: Permission on Web Tasks Table - SQL Server 2005'
print 'Control: Production Support Role - SQL Server 2005'
go
EXEC sp_helprotect
go

/* Control: Test Access to Privileged IT Functions */

print '==============================================================================='
print 'Stored procedure: SP_HELPROLEMEMBER'
print 'Control: Test Access to Privileged IT Functions'
go
sp_helprolemember
go
