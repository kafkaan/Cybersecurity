# LLMNR/NBT-NS Poisoning - from Linux

### <mark style="color:red;">LLMNR & NBT-NS Primer</mark>

{% hint style="warning" %}
<mark style="color:green;">**Link-Local Multicast Name Resolution**</mark>**&#x20;(LLMNR)** et <mark style="color:green;">**NetBIOS Name Service**</mark>**&#x20;(NBT-NS)** sont des composants de Microsoft Windows qui servent de méthodes alternatives d'identification des hôtes lorsqu'une résolution DNS échoue.

Lorsqu'une machine tente de résoudre un hôte mais que la résolution DNS échoue, en général, la machine essaie de demander à toutes les autres machines du réseau local de lui fournir l'adresse correcte de l'hôte via **LLMNR**. LLMNR est basé sur le format du **Domain Name System (DNS)** et permet aux hôtes sur le même lien local d'effectuer une résolution de noms pour d'autres hôtes. Il utilise par défaut le port <mark style="color:green;">**5355**</mark> sur UDP.

Si LLMNR échoue, le **NBT-NS** est utilisé. NBT-NS identifie les systèmes sur un réseau local par leur nom **NetBIOS**. NBT-NS utilise le port <mark style="color:green;">**137**</mark> sur UDP.

Ce qui rend cette situation dangereuse, c'est que lorsque LLMNR et NBT-NS sont utilisés pour la résolution de noms, **n'importe quel hôte du réseau peut répondre**. C'est ici qu'intervient un outil comme **Responder** pour empoisonner ces requêtes. Avec un accès au réseau, nous pouvons usurper une source de résolution de noms autoritaire (dans ce cas, un hôte censé appartenir au même segment de réseau) dans le domaine de diffusion en répondant aux requêtes LLMNR et NBT-NS comme si nous avions une réponse pour l'hôte demandeur. Cette opération d'empoisonnement vise à faire en sorte que les victimes communiquent avec notre système en prétendant que notre système malveillant connaît l'emplacement de l'hôte demandé.

Si l'hôte demandé nécessite une résolution de noms ou des actions d'authentification, nous pouvons capturer le <mark style="color:green;">**hachage NetNTLM**</mark> et tenter de le casser par une attaque par force brute hors ligne pour récupérer le mot de passe en clair. La demande d'authentification capturée peut également être relayée pour accéder à un autre hôte ou utilisée contre un autre protocole (comme LDAP) sur le même hôte.

Le **spoofing LLMNR/NBNS**, combiné à l'absence de signature SMB, peut souvent conduire à un accès **administratif** sur les hôtes au sein d'un domaine. Les attaques **SMB Relay** seront couvertes dans un module ultérieur concernant les déplacements latéraux.
{% endhint %}

***

### <mark style="color:red;">Quick Example - LLMNR/NBT-NS Poisoning</mark>

1. A host attempts to connect to the print server at \\\print01.inlanefreight.local, but accidentally types in \\\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

***

### <mark style="color:red;">TTPs</mark>

We are performing these actions to collect authentication information sent over the network in the form of NTLMv1 and NTLMv2 password hashes.

&#x20;As discussed in the [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory) module, NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash.

{% hint style="info" %}
Responder is written in Python and typically used on a Linux attack host, though there is a .exe version that works on Windows. Inveigh is written in both C# and PowerShell (considered legacy). Both tools can be used to attack the following protocols:

* LLMNR
* DNS
* MDNS
* NBNS
* DHCP
* ICMP
* HTTP
* HTTPS
* SMB
* LDAP
* WebDAV
* Proxy Auth

Responder also has support for:

* MSSQL
* DCE-RPC
* FTP, POP3, IMAP, and SMTP auth
{% endhint %}

***

#### <mark style="color:green;">Responder In Action</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ responder -h
```
{% endcode %}

{% hint style="warning" %}
Comme indiqué plus tôt dans le module, l'option **-A** nous place en mode analyse, ce qui nous permet de voir les demandes **NBT-NS**, **BROWSER** et **LLMNR** dans l'environnement sans empoisonner les réponses. Nous devons toujours spécifier soit une interface, soit une adresse IP.

Voici quelques options courantes que nous utiliserons typiquement :

* **-wf** : Cette option démarre le serveur proxy malveillant WPAD.
* **-f** : Elle tente de déterminer le système d'exploitation et la version du serveur distant.
* **-v** : Cette option augmente la verbosité des sorties, ce qui peut être utile si nous rencontrons des problèmes, mais cela génère beaucoup de données supplémentaires affichées dans la console.

D'autres options comme **-F** et **-P** peuvent être utilisées pour forcer l'authentification **NTLM** ou **Basic**, et pour forcer l'authentification proxy, mais elles peuvent entraîner une invite de connexion, donc elles doivent être utilisées avec précaution.

L'option **-w** active le serveur proxy WPAD intégré. Cela peut être très efficace, surtout dans de grandes organisations, car il captera toutes les requêtes HTTP de n'importe quel utilisateur qui utilise Internet Explorer, à condition que le navigateur ait les paramètres de détection automatique activés.

Avec cette configuration, **Responder** écoutera et répondra à toutes les demandes qu'il verra sur le réseau. Si l'attaque réussit et que nous parvenons à capturer un hachage, **Responder** l'affichera à l'écran et l'écrira dans un fichier journal par hôte situé dans le répertoire **/usr/share/responder/logs**.

&#x20;Les hachages sont enregistrés au format **(NOM\_MODULE)-(TYPE\_HACHAGE)-(IP\_CLIENT).txt**, et un hachage est imprimé à la console et stocké dans son fichier journal associé, sauf si le mode **-v** est activé. Par exemple, un fichier journal pourrait ressembler à **SMB-NTLMv2-SSP-172.16.5.25**.

Les hachages sont également stockés dans une base de données **SQLite** qui peut être configurée dans le fichier de configuration **Responder.conf**, généralement situé dans **/usr/share/responder**, à moins que nous ne clonions directement le dépôt **Responder** depuis GitHub.
{% endhint %}

{% code overflow="wrap" fullWidth="true" %}
```shell-session
UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353
```
{% endcode %}

Any of the rogue servers (i.e., SMB) can be disabled in the `Responder.conf` file.

<mark style="color:green;">**Responder Logs**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ls

Analyzer-Session.log                Responder-Session.log
Config-Responder.log                SMB-NTLMv2-SSP-172.16.5.200.txt
HTTP-NTLMv2-172.16.5.200.txt        SMB-NTLMv2-SSP-172.16.5.25.txt
Poisoners-Session.log               SMB-NTLMv2-SSP-172.16.5.50.txt
Proxy-Auth-NTLMv2-172.16.5.200.txt
```

<mark style="color:green;">**Starting Responder with Default Settings**</mark>

```bash
sudo responder -I ens224 
```

<mark style="color:green;">**Capturing with Responder**</mark>

Typically we should start Responder and let it run for a while in a tmux window while we perform other enumeration tasks to maximize the number of hashes that we can obtain. Once we are ready, we can pass these hashes to Hashcat using hash **mode `5600` for NTLMv2** hashes that we typically obtain with Responder.&#x20;

<mark style="color:green;">**Cracking an NTLMv2 Hash With Hashcat**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt 

```
{% endcode %}

***
