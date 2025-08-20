---
description: >-
  https://www.hack-notes.pro/academy-hackthebox/attacking-common-services/attacking-common-services-easy
---

# Attacking Common Services

***

## <mark style="color:red;">File Share Services</mark>

Un service de partage de fichiers est un type de service qui fournit, gère et surveille le transfert de fichiers informatiques. Il y a quelques années, les entreprises utilisaient couramment uniquement des services internes pour le partage de fichiers, tels que SMB, NFS, FTP, TFTP, SFTP, mais avec l'adoption croissante du cloud, la plupart des entreprises utilisent désormais également des services cloud tiers tels que Dropbox, Google Drive, OneDrive, SharePoint, ou d'autres formes de stockage de fichiers comme AWS S3, Azure Blob Storage ou Google Cloud Storage.

***

## <mark style="color:red;">Server Message Block (SMB)</mark>

SMB is commonly used in Windows networks, and we will often find share folders in a Windows network.

### <mark style="color:blue;">**Windows**</mark>

&#x20;On Windows GUI, we can press `[WINKEY] + [R]` to open the Run dialog box and type the file share location, e.g.: `\\192.168.220.129\Finance\`

![text](https://academy.hackthebox.com/storage/modules/116/windows_run_sharefolder2.jpg)

Suppose the shared folder allows anonymous authentication, or we are authenticated with a user who has privilege over that shared folder. In that case, we will not receive any form of authentication request, and it will display the content of the shared folder.

If we do not have access, we will receive an authentication request.

![text](https://academy.hackthebox.com/storage/modules/116/auth_request_share_folder2.jpg)

#### <mark style="color:green;">**Windows CMD - DIR**</mark>

```cmd-session
C:\htb> dir \\192.168.220.129\Finance\
```

The command [net use](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155\(v=ws.11\)) connects a computer to or disconnects a computer from a shared resource or displays information about computer connections. **We can connect to a file share with the following command and map its content to the drive letter `n`.**

#### <mark style="color:green;">**Windows CMD - Net Use**</mark>

```cmd-session
C:\htb> net use n: \\192.168.220.129\Finance
```

```cmd-session
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

#### <mark style="color:green;">**Windows CMD - DIR**</mark>

```cmd-session
C:\htb> dir n: /a-d /s /b | find /c ":\"
```

We found 29,302 files. Let's walk through the command:

&#x20; Interacting with Common Services

```shell-session
dir n: /a-d /s /b | find /c ":\"
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Syntax</strong></td><td><strong>Description</strong></td></tr><tr><td><code>dir</code></td><td>Application</td></tr><tr><td><code>n:</code></td><td>Directory or drive to search</td></tr><tr><td><code>/a-d</code></td><td><code>/a</code> is the attribute and <code>-d</code> means not directories</td></tr><tr><td><code>/s</code></td><td>Displays files in a specified directory and all subdirectories</td></tr><tr><td><code>/b</code></td><td>Uses bare format (no heading information or summary)</td></tr></tbody></table>

The following command `| find /c ":\\"` process the output of `dir n: /a-d /s /b` to count how many files exist in the directory and subdirectories. You can use `dir /?` to see the full help. Searching through 29,302 files is time consuming, scripting and command line utilities can help us speed up the search. With `dir` we can search for specific names in files such as:

* cred
* password
* users
* secrets
* key
* Common File Extensions for source code such as: .cs, .c, .go, .java, .php, .asp, .aspx, .html.

```cmd-session
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt


C:\htb>dir n:\*secret* /s /b

n:\Contracts\private\secret.txt
```

If we want to search for a specific word within a text file, we can use [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr).

#### <mark style="color:green;">**Windows CMD - Findstr**</mark>

```cmd-session
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

We can find more `findstr` examples [here](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples).

***

#### <mark style="color:green;">**Windows PowerShell**</mark>

```powershell-session
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

Instead of `net use`, we can use `New-PSDrive` in PowerShell.

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```
{% endcode %}

To provide a username and password with Powershell, we need to create a [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential). I

#### <mark style="color:green;">**Windows PowerShell - PSCredential Object**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```
{% endcode %}

#### <mark style="color:green;">**Windows PowerShell - GCI**</mark>

```powershell-session
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

We can use the property `-Include` to find specific items from the directory specified by the Path parameter.

```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

The `Select-String` cmdlet uses regular expression matching to search for text patterns in input strings and files. We can use `Select-String` similar to `grep` in UNIX or `findstr.exe` in Windows.

#### <mark style="color:green;">**Windows PowerShell - Select-String**</mark>

```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

***

### <mark style="color:blue;">**Linux**</mark>

<mark style="color:orange;">**Linux - Mount**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo mkdir /mnt/Finance
mrroboteLiot@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```
{% endcode %}

As an alternative, we can use a credential file.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```
{% endcode %}

The file `credentialfile` has to be structured like this:

<mark style="color:orange;">**CredentialFile**</mark>

```txt
username=plaintext
password=Password123
domain=.
```

Note: We need to install `cifs-utils` to connect to an SMB share folder. To install it we can execute from the command line `sudo apt install cifs-utils`.

<mark style="color:orange;">**Linux - Find**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

Next, let's find files that contain the string `cred`:

```shell-session
mrroboteLiot@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

***

## <mark style="color:red;">Other Services</mark>

***

### <mark style="color:blue;">Email - Protocoles et Clients</mark>

#### <mark style="color:green;">Protocoles d'Envoi et de Réception :</mark>

* **SMTP (Simple Mail Transfer Protocol)** : Envoi d'e-mails.
* **POP3 (Post Office Protocol v3)** : Récupération d'e-mails (stockage local).
* **IMAP (Internet Message Access Protocol)** : Récupération d'e-mails (stockage sur serveur).

#### <mark style="color:green;">Clients de Messagerie :</mark>

* **Linux :** Evolution (GNOME), Thunderbird, Mutt
* **Windows :** Outlook, Thunderbird
*   **Commande d'installation Evolution :**

    ```bash
    sudo apt-get install evolution
    ```
*   **En cas d'erreur Evolution :**

    ```bash
    export WEBKIT_FORCE_SANDBOX=0 && evolution
    ```

#### <mark style="color:green;">Connexion sécurisée :</mark>

* **SMTPS** : SMTP over SSL (port dédié).
* **STARTTLS** : Upgrade vers TLS après connexion.
* **IMAPS** : IMAP over SSL.

***

### <mark style="color:blue;">Bases de Données (SQL et NoSQL)</mark>

#### <mark style="color:green;">Types de Bases de Données :</mark>

* **Hiérarchique**
* **NoSQL (non relationnel)**
* **SQL (relationnel)** : MySQL, MSSQL

#### <mark style="color:green;">Modes d'Interaction :</mark>

1. **Utilitaires en ligne de commande** : `mysql`, `sqlcmd`, `sqsh`
2. **Langages de programmation** : Python, Java
3. **Applications GUI** : HeidiSQL, MySQL Workbench, SSMS

#### <mark style="color:green;">MySQL - Exemples de Commandes :</mark>

*   **Linux :**

    ```bash
    mysql -u username -pPassword123 -h 10.129.20.13
    ```
*   **Windows :**

    ```bash
    mysql.exe -u username -pPassword123 -h 10.129.20.13
    ```

#### <mark style="color:green;">MSSQL - Exemples de Commandes :</mark>

*   **Linux :**

    ```bash
    sqsh -S 10.129.20.13 -U username -P Password123
    ```
*   **Windows :**

    ```bash
    sqlcmd -S 10.129.20.13 -U username -P Password123
    ```

#### <mark style="color:green;">Applications GUI :</mark>

* **MySQL :** MySQL Workbench
* **MSSQL :** SQL Server Management Studio (SSMS)
* **Outil multi-plateforme :** dbeaver

<mark style="color:orange;">**Installation de dbeaver :**</mark>

```bash
sudo dpkg -i dbeaver-<version>.deb
```

<mark style="color:orange;">**Lancer dbeaver :**</mark>

```bash
dbeaver &
```

***

### <mark style="color:blue;">Outils d'Interaction avec les Services Courants</mark>

#### <mark style="color:green;">Partage de Fichiers (SMB, FTP) :</mark>

* **SMB :** smbclient, CrackMapExec, Impacket (psexec.py)
* **FTP :** ftp, lftp, ncftp, filezilla

#### <mark style="color:green;">Email</mark> :

* **Clients :** Thunderbird, Claws Mail, Mutt
* **Outils SMTP :** sendEmail, swaks, sendmail

#### <mark style="color:green;">Bases de Données :</mark>

* **MySQL :** mycli, MySQL Workbench
* **MSSQL :** mssql-cli, dbeaver, SSMS

***

### <mark style="color:blue;">Résolution de Problèmes Courants</mark>

#### <mark style="color:green;">**Problèmes Fréquents :**</mark>

1. **Authentification** : Mauvais identifiants.
2. **Privilèges** : Droits insuffisants.
3. **Connexion Réseau** : Câbles, IP, ports.
4. **Pare-feu** : Accès bloqué.
5. **Protocole** : Support non disponible.

**Solution :** Analyser les codes d'erreur et consulter la documentation officielle ou les forums.

**Tools to Interact with Common Services**

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com)            | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |

***
