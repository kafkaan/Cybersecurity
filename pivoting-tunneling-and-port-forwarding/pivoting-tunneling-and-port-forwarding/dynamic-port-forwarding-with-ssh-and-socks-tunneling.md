# Dynamic Port Forwarding with SSH and SOCKS Tunneling

***

### <mark style="color:red;">Port Forwarding in Context</mark>

`Port forwarding` is a technique that allows us to **redirect a communication request from one port to another.** Port forwarding uses TCP as the primary communication layer to provide interactive communication for the forwarded port. However, different application layer protocols such as SSH or even [SOCKS](https://en.wikipedia.org/wiki/SOCKS) (non-application layer) can be used to encapsulate the forwarded traffic. This can be effective in **bypassing firewalls and using existing services on your compromised host to pivot to other networks.**

***

### <mark style="color:red;">SSH Local Port Forwarding</mark>

![](https://academy.hackthebox.com/storage/modules/158/11.png)

We have our attack host (10.10.15.x) and a target Ubuntu server (10.129.x.x), which we have compromised. We will scan the target Ubuntu server using Nmap to search for open ports.

<mark style="color:green;">**Scanning the Pivot Target**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ nmap -sT -p22,3306 10.129.202.64
-------------------------------------------------------
PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql
```

The Nmap output shows that the SSH port is open. To access the MySQL service, we can either SSH into the server and access MySQL from inside the Ubuntu server, or we can port forward it to our localhost on port `1234` and access it locally. A benefit of accessing it locally is if we want to execute a remote exploit on the MySQL service, we won't be able to do it without port forwarding. This is due to MySQL being hosted locally on the Ubuntu server on port `3306`. So, we will use the below command to forward our local port (1234) over SSH to the Ubuntu server.

<mark style="color:green;">**Executing the Local Port Forward**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port `1234` to `localhost:3306` on the Ubuntu server. By doing this, we should be able to access the MySQL service locally on port 1234. We can use Netstat or Nmap to query our local host on 1234 port to verify whether the MySQL service was forwarded.

<mark style="color:green;">**Confirming Port Forward with Netstat**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ netstat -antp | grep 1234

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh            
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh     
```
{% endcode %}

<mark style="color:green;">**Confirming Port Forward with Nmap**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ nmap -v -sV -p1234 localhost

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```
{% endcode %}

Similarly, if we want to forward multiple ports from the Ubuntu server to your localhost, you can do so by including the `local port:server:port` argument to your ssh command. For example, the below command forwards the apache web server's port 80 to your attack host's local port on `8080`.

<mark style="color:green;">**Forwarding Multiple Ports**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```
{% endcode %}

***

### <mark style="color:red;">Setting up to Pivot</mark>

Now, if you type `ifconfig` on the Ubuntu host, you will find that this server has multiple NICs:

* One connected to our attack host (`ens192`)
* One communicating to other hosts within a different network (`ens224`)
* The loopback interface (`lo`).

**Looking for Opportunities to Pivot using ifconfig**

```shell-session
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Contrairement au scénario précédent où nous savions quel port accéder, dans notre scénario actuel, nous ne savons pas quels services se trouvent de l'autre côté du réseau. Donc, nous pouvons scanner des plages d'IP plus petites sur le réseau (172.16.5.1-200) ou le sous-réseau entier (172.16.5.0/23). Nous ne pouvons pas effectuer ce scan directement depuis notre hôte d'attaque car il n'a pas de routes vers le réseau 172.16.5.0/23. Pour ce faire, nous devrons effectuer un <mark style="color:orange;">**forwarding dynamique de port**</mark> et faire passer nos paquets réseau via le serveur Ubuntu. Nous pouvons le faire en lançant un écouteur SOCKS sur notre hôte local (hôte d'attaque personnel ou Pwnbox), puis configurer SSH pour transférer ce trafic via SSH vers le réseau (172.16.5.0/23) après s'être connecté à l'hôte cible.

Cela s'appelle le <mark style="color:orange;">**tunneling SSH via un proxy SOCKS**</mark><mark style="color:orange;">.</mark>&#x20;

{% hint style="warning" %}
**SOCKS** signifie **Socket Secure**, un protocole qui aide à communiquer avec des serveurs où des restrictions de pare-feu sont en place. Contrairement à la plupart des cas où vous initieriez une connexion pour vous connecter à un service, dans le cas de SOCKS, le trafic initial est généré par un client SOCKS, qui se connecte au serveur SOCKS contrôlé par l'utilisateur qui veut accéder à un service du côté client. Une fois la connexion établie, le trafic réseau peut être routé via le serveur SOCKS pour le compte du client connecté.
{% endhint %}

Cette technique est souvent utilisée pour contourner les restrictions imposées par les pare-feu, et permettre à une entité externe de contourner le pare-feu et d'accéder à un service dans l'environnement protégé par le pare-feu. Un autre avantage de l'utilisation d'un proxy SOCKS pour pivoter et transférer des données est que les proxys SOCKS peuvent pivoter en créant une route vers un serveur externe depuis des réseaux NAT. Les proxies SOCKS sont actuellement de deux types : **SOCKS4** et **SOCKS5**. **SOCKS4** ne fournit pas d'authentification ni de prise en charge de UDP, tandis que **SOCKS5**

![](https://academy.hackthebox.com/storage/modules/158/22.png)

In the above image, the attack host starts the SSH client and requests the SSH server to allow it to send some TCP data over the ssh socket. The SSH server responds with an acknowledgment, and the SSH client then starts listening on `localhost:9050`. Whatever data you send here will be broadcasted to the entire network (172.16.5.0/23) over SSH. We can use the below command to perform this dynamic port forwarding.

<mark style="color:green;">**Enabling Dynamic Port Forwarding with SSH**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ ssh -D 9050 ubuntu@10.129.202.64
```

The `-D` argument requests the SSH server to enable dynamic port forwarding. Once we have this enabled, we will require a tool that can route any tool's packets over the port `9050`. We can do this using the tool `proxychains`, which is capable of redirecting TCP connections through TOR, SOCKS, and HTTP/HTTPS proxy servers and also allows us to chain multiple proxy servers together. Using proxychains, we can hide the IP address of the requesting host as well since the receiving host will only see the IP of the pivot host. Proxychains is often used to force an application's `TCP traffic` to go through hosted proxies like `SOCKS4`/`SOCKS5`, `TOR`, or `HTTP`/`HTTPS` proxies.

To inform proxychains that we must use port 9050, we must modify the proxychains configuration file located at `/etc/proxychains.conf`. We can add `socks4 127.0.0.1 9050` to the last line if it is not already there.

<mark style="color:green;">**Checking /etc/proxychains.conf**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

Now when you start Nmap with proxychains using the below command, it will route all the packets of Nmap to the local port 9050, where our SSH client is listening, which will forward all the packets over SSH to the 172.16.5.0/23 network.

<mark style="color:green;">**Using Nmap with Proxychains**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200
```

This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called `SOCKS tunneling`. One more important note to remember here is that we can only perform a `full TCP connect scan` over proxychains. The reason for this is that proxychains cannot understand partial packets. If you send partial packets like half connect scans, it will return incorrect results. We also need to make sure we are aware of the fact that `host-alive` checks may not work against Windows targets because the Windows Defender firewall blocks ICMP requests (traditional pings) by default.

[A full TCP connect scan](https://nmap.org/book/scan-methods-connect-scan.html) without ping on an entire network range will take a long time. So, for this module, we will primarily focus on scanning individual hosts, or smaller ranges of hosts we know are alive, which in this case will be a Windows host at `172.16.5.19`.

{% hint style="info" %}
**Nmap envoie ses paquets** → **Interceptés par Proxychains** → **Envoyés via SOCKS5 (port 9050)** → **Transmis via SSH vers l’hôte pivot (10.129.202.64)** → **Puis redirigés vers la vraie cible (10.10.10.10)**.
{% endhint %}

<mark style="color:green;">**Enumerating the Windows Target through Proxychains**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains nmap -v -Pn -sT 172.16.5.19
Discovered open port 139/tcp on 172.16.5.19
```

The Nmap scan shows several open ports, one of which is `RDP port` (3389). Similar to the Nmap scan, we can also pivot `msfconsole` via proxychains to perform vulnerable RDP scans using Metasploit auxiliary modules. We can start msfconsole with proxychains.

***

### <mark style="color:red;">Using Metasploit with Proxychains</mark>

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.

```shell-session
mrroboteLiot@htb[/htb]$ proxychains msfconsole

msf6 > 
```

Let's use the `rdp_scanner` auxiliary module to check if the host on the internal network is listening on 3389.

<mark style="color:green;">**Using rdp\_scanner Module**</mark>

{% code fullWidth="true" %}
```shell-session
msf6 > search rdp_scanner
msf6 > use 0
msf6 auxiliary(scanner/rdp/rdp_scanner) > set rhosts 172.16.5.19
rhosts => 172.16.5.19
msf6 auxiliary(scanner/rdp/rdp_scanner) > run
```
{% endcode %}

At the bottom of the output above, we can see the RDP port open with the Windows OS version.

Depending on the level of access we have to this host during an assessment, we may try to run an exploit or log in using gathered credentials. For this module, we will log in to the Windows remote host over the SOCKS tunnel. This can be done using `xfreerdp`. The user in our case is `victor,` and the password is `pass@123`

<mark style="color:green;">**Using xfreerdp with Proxychains**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
{% endcode %}

The xfreerdp command will require an RDP certificate to be accepted before successfully establishing the session. After accepting it, we should have an RDP session, pivoting via the Ubuntu server.

<mark style="color:green;">**Successful RDP Pivot**</mark>

![RDP Pivot](https://academy.hackthebox.com/storage/modules/158/proxychaining.png)
