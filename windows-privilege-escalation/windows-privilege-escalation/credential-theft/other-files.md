# Other Files

***

{% hint style="info" %}
In an Active Directory environment, we can use a tool such as [Snaffler](https://github.com/SnaffCon/Snaffler) to crawl network share drives for interesting file extensions such as `.kdbx`, `.vmdk`, `.vdhx`, `.ppk`, etc.&#x20;
{% endhint %}

***

### <mark style="color:red;">Manually Searching the File System for Credentials</mark>

* [this cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/).

<mark style="color:green;">**Search File Contents for String - Example 1**</mark>

{% code fullWidth="true" %}
```powershell
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```
{% endcode %}

<mark style="color:green;">**Search File Contents for String - Example 2**</mark>

<pre class="language-powershell" data-full-width="true"><code class="lang-powershell"><strong>findstr /si password *.xml *.ini *.txt *.config
</strong></code></pre>

<mark style="color:green;">**Search File Contents for String - Example 3**</mark>

* **`/s`** : Recherche dans les sous-répertoires du répertoire actuel. Cela signifie que la commande va chercher dans tous les fichiers du répertoire et dans ses sous-dossiers.
* **`/p`** : Ignore les fichiers contenant des caractères non imprimables. Cela permet d'éviter d'analyser des fichiers qui ne sont pas textuels.
* **`/i`** : Recherche insensible à la casse. Cela permet de trouver "password", "Password", "PASSWORD", etc.
* **`/n`** : Affiche le numéro de ligne où la chaîne recherchée a été trouvée dans chaque fichier.

{% code fullWidth="true" %}
```powershell
findstr /spin "password" *.*
```
{% endcode %}

<mark style="color:green;">**Search File Contents with PowerShell**</mark>

{% code fullWidth="true" %}
```powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```
{% endcode %}

<mark style="color:green;">**Search for File Extensions - Example 1**</mark>

{% code fullWidth="true" %}
```powershell
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```
{% endcode %}

<mark style="color:green;">**Search for File Extensions - Example 2**</mark>

```powershell
where /R C:\ *.config
```

Similarly, we can search the file system for certain file extensions with a command such as:

<mark style="color:green;">**Search for File Extensions Using PowerShell**</mark>

{% code fullWidth="true" %}
```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```
{% endcode %}

***

### <mark style="color:red;">Sticky Notes Passwords</mark>

<mark style="color:green;">**Looking for StickyNotes DB Files**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> ls
 
 
    Directory: C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
 
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----         5/25/2021  11:59 AM            982 Ecs.dat
-a----         5/25/2021  11:59 AM           4096 plum.sqlite
-a----         5/25/2021  11:59 AM          32768 plum.sqlite-shm
-a----         5/25/2021  12:00 PM         197792 plum.sqlite-wal
```
{% endcode %}

We can copy the three `plum.sqlite*` files down to our system and open them with a tool such as [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the `Text` column in the `Note` table with the query `select Text from Note;`.

<figure><img src="../../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Viewing Sticky Notes Data Using PowerShell**</mark>

{% code fullWidth="true" %}
```powershell-session
Set-ExecutionPolicy Bypass -Scope Process

cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```
{% endcode %}

<mark style="color:green;">**Strings to View DB File Contents**</mark>

```shell-session
strings plum.sqlite-wal
```

***

### <mark style="color:red;">Other Files of Interest</mark>

```shell-session
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

#### 🔹 Fichiers système et de configuration

**`%SYSTEMDRIVE%\pagefile.sys`**

* **Contenu :** Fichier d’échange (ou mémoire virtuelle) utilisé quand la RAM est pleine. Windows y écrit des données pour éviter des plantages.
* **Utilité :** Améliorer la gestion mémoire.

**`%WINDIR%\repair\sam`**

* **Contenu :** Sauvegarde du fichier SAM (Security Account Manager), qui contient les comptes utilisateurs et les hachages de mots de passe.
* **Utilité :** Restaurer les comptes utilisateurs après un crash.

**`%WINDIR%\repair\system`, `software`, `security`**

* **Contenu :** Sauvegardes du registre système (paramètres système, logiciels installés, règles de sécurité).
* **Utilité :** Récupération du système en cas de problème de démarrage.

**`%WINDIR%\system32\config\*.sav`**

* **Contenu :** Sauvegardes automatiques des ruches du registre :
  * `default.sav` → valeurs par défaut utilisateur
  * `security.sav` → politiques de sécurité
  * `software.sav` → logiciels installés
  * `system.sav` → configuration système
* **Utilité :** Restaurer le registre si corrompu.

***

#### 🔹 Journaux système

**`%WINDIR%\debug\NetSetup.log`**

* **Contenu :** Journal de la configuration réseau, notamment l’ajout d’un PC à un domaine.
* **Utilité :** Débogage lors de problèmes d’intégration au domaine Active Directory.

**`%WINDIR%\iis6.log`**

* **Contenu :** Journal d’installation ou de fonctionnement d’IIS 6 (Internet Information Services).
* **Utilité :** Diagnostic de l’installation ou du comportement du serveur web IIS.

**`%WINDIR%\system32\config\AppEvent.Evt`**

* **Contenu :** Journal des événements d’application de Windows (ancien format .evt).
* **Utilité :** Suivi des erreurs et alertes des applications.

**`%WINDIR%\system32\config\SecEvent.Evt`**

* **Contenu :** Journal des événements de sécurité (logins, accès refusés, etc.).
* **Utilité :** Audit de la sécurité, détection d’activités suspectes.

***

#### 🔹 Logs de Windows et des outils Microsoft

**`%WINDIR%\system32\CCM\logs\*.log`**

* **Contenu :** Journaux de SCCM (System Center Configuration Manager).
* **Utilité :** Déploiement logiciel, mises à jour, gestion des postes.

***

#### 🔹 Fichiers utilisateurs

**`%USERPROFILE%\ntuser.dat`**

* **Contenu :** Fichier de registre contenant les paramètres de l’utilisateur (bureau, imprimantes, préférences).
* **Utilité :** Chargé à chaque connexion de l’utilisateur.

**`%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat`**

* **Contenu :** Fichier utilisé par Internet Explorer pour stocker l’historique, les cookies, le cache.
* **Utilité :** Navigation web (aujourd’hui obsolète mais utilisé sur anciens Windows).

***

#### 🔹 Réseau et Internet

**`%WINDIR%\System32\drivers\etc\hosts`**

* **Contenu :** Fichier de correspondance entre noms de domaine et adresses IP, utilisé avant DNS.
* **Utilité :** Forcer des résolutions de noms (ex. : bloquer un site ou rediriger un domaine).

***

#### 🔹 Configurations diverses

**`C:\ProgramData\Configs\*`**

* **Contenu :** Dossiers de configuration partagés par certains logiciels installés (selon les programmes présents).
* **Utilité :** Stocker les préférences ou données partagées entre tous les utilisateurs.

**`C:\Program Files\Windows PowerShell\*`**

* **Contenu :** Contient l’environnement PowerShell, ses modules, exécutables et scripts.
* **Utilité :** Administration avancée du système Windows.
