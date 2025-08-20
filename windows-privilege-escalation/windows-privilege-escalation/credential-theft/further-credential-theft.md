# Further Credential Theft

***

### <mark style="color:red;">Cmdkey Saved Credentials</mark>

<mark style="color:green;">**Listing Saved Credentials**</mark>

{% hint style="warning" %}
La commande **`cmdkey`** permet de **créer, lister et supprimer des noms d’utilisateur et des mots de passe enregistrés**.\
Les utilisateurs peuvent vouloir enregistrer des identifiants pour un hôte spécifique, ou bien les utiliser pour des connexions via les **services de bureau à distance (Remote Desktop / RDP)** afin de se connecter à une machine distante **sans avoir à entrer le mot de passe à chaque fois**.

Cela peut nous aider :

* soit à effectuer un **mouvement latéral** vers un autre système avec un autre utilisateur,
* soit à **escalader les privilèges** sur la machine actuelle, en exploitant les **identifiants stockés d’un autre utilisateur**.
{% endhint %}

```cmd-session
cmdkey /list
```

<figure><img src="../../../.gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Run Commands as Another User**</mark>

```powershell-session
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

***

### <mark style="color:red;">Browser Credentials</mark>

<mark style="color:green;">**Retrieving Saved Credentials from Chrome**</mark>

{% code fullWidth="true" %}
```powershell-session
.\SharpChrome.exe logins /unprotect
```
{% endcode %}

{% hint style="warning" %}
Note: Credential collection from Chromium-based browsers generates additional events that could be logged and identified as `4983`, `4688`, and `16385`, and monitored by the blue team.
{% endhint %}

***

### <mark style="color:red;">Password Managers</mark>

<mark style="color:green;">**Extracting KeePass Hash**</mark>

{% code fullWidth="true" %}
```shell-session
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 
```
{% endcode %}

<mark style="color:green;">**Cracking Hash Offline**</mark>

{% code fullWidth="true" %}
```shell-session
hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```
{% endcode %}

***

### <mark style="color:red;">Email</mark>

[MailSniper](https://github.com/dafthack/MailSniper).

***

### <mark style="color:red;">More Fun with Credentials</mark>

[LaZagne](https://github.com/AlessandroZ/LaZagne)

<mark style="color:green;">**Viewing LaZagne Help Menu**</mark>

{% code fullWidth="true" %}
```powershell-session
.\lazagne.exe -h
```
{% endcode %}

<mark style="color:green;">**Running All LaZagne Modules**</mark>

```powershell-session
.\lazagne.exe all
```

***

### <mark style="color:red;">Even More Fun with Credentials</mark>

[SessionGopher](https://github.com/Arvanaghi/SessionGopher)

<mark style="color:green;">**Running SessionGopher as Current User**</mark>

{% code fullWidth="true" %}
```powershell-session
Import-Module .\SessionGopher.ps1
 
Invoke-SessionGopher -Target WINLPE-SRV01
```
{% endcode %}

***

### <mark style="color:red;">Clear-Text Password Storage in the Registry</mark>

#### <mark style="color:green;">Windows AutoLogon</mark>

{% hint style="warning" %}
**Windows Autologon** est une fonctionnalité qui permet à un utilisateur de configurer son système d'exploitation Windows pour se connecter automatiquement à un compte utilisateur spécifique, sans nécessiter de saisie manuelle du nom d'utilisateur et du mot de passe à chaque démarrage. Cependant, une fois cette fonctionnalité configurée, le nom d'utilisateur et le mot de passe sont stockés dans le registre, en texte clair. Cette fonctionnalité est couramment utilisée sur des systèmes à utilisateur unique ou dans des situations où la commodité prime sur le besoin de sécurité renforcée.

Les clés de registre associées à **Autologon** se trouvent sous **HKEY\_LOCAL\_MACHINE** dans la ruche suivante, et peuvent être accessibles par des utilisateurs standards :
{% endhint %}

```cmd
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

<mark style="color:green;">**Enumerating Autologon with reg.exe**</mark>

{% code fullWidth="true" %}
```cmd-session
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```
{% endcode %}

{% hint style="danger" %}
`Note:` If you absolutely must configure Autologon for your windows system, it is recommended to use Autologon.exe from the Sysinternals suite, which will encrypt the password as an LSA secret.
{% endhint %}

#### <mark style="color:green;">Putty</mark>

{% hint style="info" %}
**Notez que les contrôles d'accès pour cette clé de registre spécifique sont liés au compte utilisateur qui a configuré et enregistré la session.**

* **Par conséquent, pour pouvoir la voir, il faudrait être connecté en tant que cet utilisateur et chercher dans la ruche `HKEY_CURRENT_USER`.**
* **Ensuite, si nous avions des privilèges administrateur, nous pourrions la trouver dans la ruche `HKEY_USERS` correspondant à cet utilisateur.**
{% endhint %}

```cmd
Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>
```

<mark style="color:green;">**Enumerating Sessions and Finding Credentials:**</mark>

{% code fullWidth="true" %}
```powershell-session
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```
{% endcode %}

{% code fullWidth="true" %}
```powershell-session
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh 
```
{% endcode %}

In this example, we can imagine the scenario that the IT administrator has configured Putty for a user in their environment, but unfortunately used their admin credentials in the proxy connection. The password could be extracted and potentially reused across the network.

{% hint style="info" %}
For additional information on `reg.exe` and working with the registry, be sure to check out the [Introduction to Windows Command Line](https://academy.hackthebox.com/module/167/section/1623) module.
{% endhint %}

***

### <mark style="color:red;">Wifi Passwords</mark>

<mark style="color:green;">**Viewing Saved Wireless Networks**</mark>

```cmd-session
netsh wlan show profile
```

<mark style="color:green;">**Retrieving Saved Wireless Passwords**</mark>

```cmd-session
netsh wlan show profile ilfreight_corp key=clear
```
