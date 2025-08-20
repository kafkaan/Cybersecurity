---
cover: ../../.gitbook/assets/ssh.jpg
coverY: 0
---

# Gestion à Distance sous Linux

***

## <mark style="color:red;">**Introduction**</mark>

La gestion à distance des serveurs Linux est essentielle pour administrer les systèmes de manière efficace, surtout lorsque les serveurs sont situés dans des lieux différents. Cette gestion peut être réalisée via plusieurs protocoles et services, chacun ayant ses propres avantages et risques.

***

## <mark style="color:red;">**1. SSH (Secure Shell)**</mark>

[**Secure Shell**](https://en.wikipedia.org/wiki/Secure_Shell) **(`SSH`)** enables two computers to establish an encrypted and direct connection within a possibly insecure network on the standard port `TCP 22`

* **Fonctionnement** : Permet d'établir une <mark style="color:orange;">**connexion sécurisée entre deux ordinateurs sur un réseau**</mark> potentiellement non sécurisé, utilisant <mark style="color:purple;">**l**</mark><mark style="color:orange;">**e port TCP 22**</mark> par défaut.
*   **Versions** :

    * **SSH-1** : Obsolète, vulnérable aux attaques MITM.
    * **SSH-2** : Amélioré en termes de chiffrement, sécurité et stabilité.

    `SSH-2`, also known as SSH version 2, is a more advanced protocol than SSH version 1 in encryption, speed, stability, and security. For example, `SSH-1` is vulnerable to `MITM` attacks, whereas SSH-2 is not.
* **Utilisations** :
  * Accès à distance via la ligne de commande ou l'interface graphique.
  * Transfert de fichiers, tunnel TCP, exécution de commandes à distance.
* **Méthodes d'authentification** :
  * **Mot de passe**
  * **Clé publique/privée**
  * **Authentification basée sur l'hôte**
  * **Challenge-response**
  * **GSSAPI**
* **Configuration par défaut** :
  * <mark style="color:orange;">**Fichier principal :**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`/etc/ssh/sshd_config`**</mark>
  * Certaines <mark style="color:orange;">**options comme le X11Forwarding sont activées par défaut mais peuvent présenter des risques.**</mark> (injection vulnerability in version 7.2p1 of OpenSSH in 2016)

```bash
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

*   **Configurations dangereuses** :

    <figure><img src="../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Footprinting the Service</mark>

```bash
mrroboteLiot@htb[/htb]$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
mrroboteLiot@htb[/htb]$ ./ssh-audit.py 10.129.14.132
```

<mark style="color:orange;">**Change Authentication Method**</mark>

```bash
mrroboteLiot@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config 
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

For potential brute-force attacks, we can specify the authentication method with the SSH client option

```
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```

{% hint style="info" %}
We may encounter various banners for the SSH server during our penetration tests. By default, the banners start with the version of the protocol that can be applied and then the version of the server itself. For example, with `SSH-1.99-OpenSSH_3.9p1`, we know that we can use both protocol versions SSH-1 and SSH-2, and we are dealing with OpenSSH server version 3.9p1. On the other hand, for a banner with `SSH-2.0-OpenSSH_8.2p1`, we are dealing with an OpenSSH version 8.2p1 which only accepts the SSH-2 protocol version.
{% endhint %}

***

## <mark style="color:red;">**2. Rsync**</mark>

{% hint style="warning" %}
[Rsync](https://linux.die.net/man/1/rsync) is a <mark style="color:orange;">**fast and efficient tool for locally and remotely copying files**</mark>. It can be used to copy files locally on a given machine and to/from remote hosts. It is highly versatile and well-known for its delta-transfer algorithm. This algorithm reduces the amount of data transmitted over the network when a version of the file already exists on the destination host. It does this by sending only the differences between the source files and the older version of the files that reside on the destination server. It is often used for backups and mirroring. It finds files that need to be transferred by looking at files that have changed in size or the last modified time.
{% endhint %}

* **Fonctionnement** : Outil rapide pour la copie de fichiers localement ou à distance, utilisant une méthode de transfert delta pour minimiser la quantité de données transmises.
* **Utilisation du port** : <mark style="color:orange;">**873**</mark> par défaut.
* **Sécurité** : Peut être configuré pour utiliser SSH pour des transferts sécurisés.
* **Exploitation potentielle** :
  * Lister les fichiers d’un dossier partagé.
  * Synchroniser des fichiers sans authentification si mal configuré.
  * Accéder à des fichiers sensibles via des partages non sécurisés.

***

### <mark style="color:blue;">**Scanning for Rsync**</mark>

```sh
mrroboteLiot@htb[/htb]$ sudo nmap -sV -p 873 127.0.0.1
```

#### <mark style="color:green;">**Probing for Accessible Shares**</mark>

We can next probe the service a bit to see what we can gain access to.

```shell-session
mrroboteLiot@htb[/htb]$ nc -nv 127.0.0.1 873

(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
#list
dev            	Dev Tools
@RSYNCD: EXIT
```

#### <mark style="color:green;">**Enumerating an Open Share**</mark>

Here we can see a share called `dev`, and we can enumerate it further.

```shell-session
mrroboteLiot@htb[/htb]$ rsync -av --list-only rsync://127.0.0.1/dev

receiving incremental file list
drwxr-xr-x             48 2022/09/19 09:43:10 .
-rw-r--r--              0 2022/09/19 09:34:50 build.sh
-rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
drwx------             54 2022/09/19 09:43:10 .ssh

sent 25 bytes  received 221 bytes  492.00 bytes/sec
total size is 0  speedup is 0.00
```

From here, we could sync all files to our attack host with the command `rsync -av rsync://127.0.0.1/dev`. If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH.This [guide](https://phoenixnap.com/kb/how-to-rsync-over-ssh) is helpful for understanding the syntax for using Rsync over SSH.

{% hint style="warning" %}
<mark style="color:blue;">**Qu'est-ce que Rsync ?**</mark>

Rsync (Remote Sync) est un utilitaire puissant utilisé pour copier et synchroniser des fichiers et des répertoires entre différents systèmes, que ce soit sur le même réseau ou à travers Internet. Rsync est efficace parce qu'il ne transfère que les différences entre les fichiers, ce qui économise la bande passante et le temps de transfert.

**Comment Rsync fonctionne-t-il ?**

1. **Connexion :** Rsync établit une connexion avec un serveur Rsync sur le port 873 (par défaut) pour transférer des fichiers.
2. **Listing des Partages :** Une fois connecté, Rsync peut lister les "partages" ou répertoires disponibles sur le serveur, un peu comme ce que tu as vu avec le partage `dev` qui correspond peut-être à des "Dev Tools".
3. **Transfert de Fichiers :** Rsync compare les fichiers entre le système source et le système cible et ne transfère que les fichiers qui ont été modifiés ou qui n'existent pas déjà sur le système cible.

**Comparaison avec NFS et SMB :**

* **NFS (Network File System) :** Un système de fichiers distribué qui permet à un utilisateur d'accéder à des fichiers sur un autre hôte comme s'ils étaient sur son propre disque dur.
  * **Utilisation :** Principalement dans les environnements Unix/Linux.
  * **Sécurité :** Accès basé sur les permissions de fichiers.
* **SMB (Server Message Block) :** Utilisé principalement dans les environnements Windows pour le partage de fichiers et d'imprimantes.
  * **Utilisation :** Environnements Windows, mais aussi disponible sur Linux via Samba.
  * **Sécurité :** Authentification utilisateur requise, souvent avec des comptes locaux ou via un domaine.
* **Rsync :** Utilisé pour synchroniser des fichiers entre deux systèmes, souvent pour des sauvegardes ou la réplication de données.
  * **Utilisation :** Sauvegardes, synchronisation de répertoires sur différents systèmes.
  * **Sécurité :** Peut être utilisé avec SSH pour chiffrer les transferts, contrairement à NFS ou SMB qui nécessitent des configurations supplémentaires pour le chiffrement.

**Exemple d'utilisation de Rsync :**

* **Sauvegarde locale :** Synchroniser un dossier local avec un dossier de sauvegarde sur le même ordinateur.
* **Sauvegarde distante :** Sauvegarder un dossier de travail sur un serveur distant via SSH.

#### **Scénario décrit avec Nmap et Nc :**

* **Nmap Scan :** Tu as utilisé Nmap pour détecter que le service Rsync est actif sur le port 873, ce qui indique qu'il est disponible pour synchroniser des fichiers.
* **Netcat (nc) :** En utilisant `nc`, tu as établi une connexion avec le service Rsync et obtenu une liste des répertoires partagés disponibles (`#list` montre `dev` comme un répertoire accessible).
{% endhint %}

***

## <mark style="color:red;">**3. R-Services**</mark>

{% hint style="info" %}
R-Services are a **suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP**. Initially developed by the Computer Systems Research Group (`CSRG`) at the University of California, Berkeley, `r-services` were the de facto standard for remote access between Unix operating systems until they were replaced by the Secure Shell (`SSH`) protocols and commands due to inherent security flaws built into them. Much like `telnet`, r-services transmit information from client to server(and vice versa.) over the network in an unencrypted format, making it possible for attackers to intercept network traffic (passwords, login information, etc.) by performing man-in-the-middle (`MITM`) attacks.
{% endhint %}

* **R-Services** : Ensemble de services pour l'accès à distance et l'exécution de commandes entre systèmes Unix, utilisant les <mark style="color:blue;">**ports 512, 513 et 514.**</mark>
* <mark style="color:orange;">**Commandes principales**</mark> <mark style="color:orange;"></mark><mark style="color:orange;">:</mark>
  * **rcp** : Copie de fichiers entre systèmes.
  * **rsh** : Ouvre un shell à distance sans procédure de connexion.
  * **rexec** : Exécution de commandes à distance après authentification.
  * **rlogin** : Connexion à distance sur un système Unix.

Each command has its intended functionality; however, we will only cover the most commonly abused `r-commands`. The table below will provide a quick overview of the most frequently abused commands, including the service daemon they interact with, over what port and transport method to which they can be accessed, and a brief description of each.

<figure><img src="../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

* <mark style="color:green;">**Problèmes de sécurité**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>
  * **Non chiffré** : Transmet les données en clair, vulnérable aux attaques MITM.
  * **Fichiers `hosts.equiv` et `.rhosts`** : Contiennent des configurations d'accès de confiance pouvant être exploitées pour se connecter sans authentification.

***

#### <mark style="color:green;">**Audit et Hardening**</mark>

* **Outil `ssh-audit`** : Permet de vérifier la configuration SSH, de détecter les algorithmes de chiffrement utilisés, et d'identifier les vulnérabilités.
* **Bonnes pratiques** :
  * Désactiver les versions et options obsolètes comme SSH-1.
  * Restreindre les authentifications par mot de passe et désactiver `PermitRootLogin`.
  * Utiliser des clés publiques/privées avec une passphrase forte.
  * Vérifier régulièrement la configuration et appliquer des guides de durcissement.

***

### <mark style="color:blue;">**Scanning for R-Services**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo nmap -sV -p 512,513,514 10.0.17.2

Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 15:02 EST
Nmap scan report for 10.0.17.2
Host is up (0.11s latency).

PORT    STATE SERVICE    VERSION
512/tcp open  exec?
513/tcp open  login?
514/tcp open  tcpwrapped

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.54 seconds
```

***

### <mark style="color:blue;">**Access Control & Trusted Relationships**</mark>

The primary concern for `r-services`, and one of the primary reasons `SSH` was introduced to replace it, is the inherent issues regarding access control for these protocols. R-services rely on trusted information sent from the remote client to the host machine they are attempting to authenticate to. By default, these services utilize [Pluggable Authentication Modules (PAM)](https://debathena.mit.edu/trac/wiki/PAM) for user authentication onto a remote system; however, <mark style="color:orange;">**`They also bypass this authentication through the use of the /etc/hosts.equiv and .rhosts`**</mark> files on the system. The `hosts.equiv` and `.rhosts` files contain a list of hosts (`IPs` or `Hostnames`) and users that are `trusted` by the local host when a connection attempt is made using `r-commands`. Entries in either file can appear like the following:

Note: The `hosts.equiv` file is recognized as the global configuration regarding all users on a system, whereas `.rhosts` provides a per-user configuration.

#### <mark style="color:green;">**Sample .rhosts File**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ cat .rhosts

htb-student     10.0.17.5
+               10.0.17.10
+               +
```

As we can see from this example, both files follow the specific syntax of `<username> <ip address>` or `<username> <hostname>` pairs. Additionally, the `+` modifier can be used within these files as a wildcard to specify anything. In this example, the `+` modifier allows any external user to access r-commands from the `htb-student` user account via the host with the IP address `10.0.17.10`.

Misconfigurations in either of these files can allow an attacker to authenticate as another user without credentials, with the potential for gaining code execution. Now that we understand how we can potentially abuse misconfigurations in these files let's attempt to try logging into a target host using `rlogin`.

***

<mark style="color:green;">**Logging in Using Rlogin**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ rlogin 10.0.17.2 -l htb-student

Last login: Fri Dec  2 16:11:21 from localhost

[htb-student@localhost ~]$
```

We have successfully logged in under the `htb-student` account on the remote host due to the misconfigurations in the `.rhosts` file. Once successfully logged in, we can also abuse the `rwho` command to list all interactive sessions on the local network by sending requests to the UDP port 513.

<mark style="color:green;">**Listing Authenticated Users Using Rwho**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ rwho

root     web01:pts/0 Dec  2 21:34
htb-student     workstn01:tty1  Dec  2 19:57  2:25       
```

From this information, we can see that the `htb-student` user is currently authenticated to the `workstn01` host, whereas the `root` user is authenticated to the `web01` host. We can use this to our advantage when scoping out potential usernames to use during further attacks on hosts over the network. However, the `rwho` daemon periodically broadcasts information about logged-on users, so it might be beneficial to watch the network traffic.

<mark style="color:green;">**Listing Authenticated Users Using Rusers**</mark>

To provide additional information in conjunction with `rwho`, we can issue the `rusers` command. This will give us a more detailed account of all logged-in users over the network, including information such as the username, hostname of the accessed machine, TTY that the user is logged in to, the date and time the user logged in, the amount of time since the user typed on the keyboard, and the remote host they logged in from (if applicable).

```shell-session
mrroboteLiot@htb[/htb]$ rusers -al 10.0.17.5

htb-student     10.0.17.5:console          Dec 2 19:57     2:25
```

As we can see, R-services are less frequently used nowadays due to their inherent security flaws and the availability of more secure protocols such as SSH. To be a well-rounded information security professional, we must have a broad and deep understanding of many systems, applications, protocols, etc. So, file away this knowledge about R-services because you never know when you may encounter them.

***
