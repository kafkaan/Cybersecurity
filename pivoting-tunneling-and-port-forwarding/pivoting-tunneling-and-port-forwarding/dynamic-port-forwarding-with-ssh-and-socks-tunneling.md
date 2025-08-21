# Dynamic Port Forwarding with SSH and SOCKS Tunneling

***

### <mark style="color:red;">Port Forwarding in Context</mark>

{% hint style="warning" %}
**Le port forwarding (redirection de port)** est une technique qui permet de rediriger une requête de communication d’un port vers un autre.\
Il utilise généralement **TCP** comme couche de communication principale pour assurer l’interactivité sur le port redirigé.\
Cependant, différents protocoles de couche applicative comme **SSH** ou encore **SOCKS** peuvent être utilisés pour encapsuler le trafic redirigé.\
Cette méthode peut servir, par exemple, à franchir certains pare-feu ou à accéder à des services disponibles sur une machine intermédiaire afin de communiquer avec d’autres réseaux.
{% endhint %}

***

### <mark style="color:red;">SSH Local Port Forwarding</mark>

![](https://academy.hackthebox.com/storage/modules/158/11.png)

<mark style="color:green;">**Scanning the Pivot Target**</mark>

```shell-session
nmap -sT -p22,3306 10.129.202.64
```

Utiliser SSH et le port forwarding pour accéder localement à un service MySQL (port 3306) d’un serveur distant via un port local (1234).

<mark style="color:green;">**Executing the Local Port Forward**</mark>

```shell-session
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

The `-L` command tells the SSH client to request the SSH server to forward all the data we send via the port `1234` to `localhost:3306` on the Ubuntu server.   &#x20;

<mark style="color:green;">**Forwarding Multiple Ports**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```
{% endcode %}

***

### <mark style="color:red;">Setting up to Pivot</mark>

**Le serveur Ubuntu possède plusieurs interfaces réseau : une vers la machine locale (ens192), une vers un autre réseau (ens224), et l’interface loopback (lo).**

```shell-session
ubuntu@WEB01:~$ ifconfig 
```

Comme nous ne savons pas quels services sont présents sur le réseau 172.16.5.0/23, nous devons le scanner via le serveur Ubuntu. Pour cela, on met en place un port forwarding dynamique avec SSH et un proxy SOCKS, ce qui permet de faire passer notre trafic vers ce réseau.

Cela s'appelle le <mark style="color:orange;">**tunneling SSH via un proxy SOCKS**</mark><mark style="color:orange;">.</mark>&#x20;

{% hint style="info" %}
**SOCKS** signifie **Socket Secure**, un protocole qui aide à communiquer avec des serveurs où des restrictions de pare-feu sont en place. Contrairement à la plupart des cas où vous initieriez une connexion pour vous connecter à un service, dans le cas de SOCKS, le trafic initial est généré par un client SOCKS, qui se connecte au serveur SOCKS contrôlé par l'utilisateur qui veut accéder à un service du côté client. Une fois la connexion établie, le trafic réseau peut être routé via le serveur SOCKS pour le compte du client connecté.

Cette technique est souvent utilisée pour contourner les restrictions imposées par les pare-feu, et permettre à une entité externe de contourner le pare-feu et d'accéder à un service dans l'environnement protégé par le pare-feu. Un autre avantage de l'utilisation d'un proxy SOCKS pour pivoter et transférer des données est que les proxys SOCKS peuvent pivoter en créant une route vers un serveur externe depuis des réseaux NAT. Les proxies SOCKS sont actuellement de deux types : **SOCKS4** et **SOCKS5**. **SOCKS4** ne fournit pas d'authentification ni de prise en charge de UDP, tandis que **SOCKS5**

***

1️⃣ Qu’est-ce qu’un proxy SOCKS ?

* **SOCKS = Socket Secure**.
* C’est un protocole qui permet à un client de demander à un serveur SOCKS de transmettre ses paquets réseau vers un autre serveur.
* Contrairement à une connexion normale, le client ne communique pas directement avec le service final : il passe par le serveur SOCKS.
* Cela sert souvent à **contourner les pare-feu** ou les restrictions réseau.

2️⃣ Comment SSH et SOCKS travaillent ensemble ?

* Quand tu fais `ssh -D 9050 utilisateur@serveur`, SSH crée un **serveur SOCKS local** sur ton ordinateur (port 9050).
* Tout trafic que tu envoies sur ce port est **encapsulé dans la connexion SSH** et envoyé vers le serveur SSH.
* Le serveur SSH le redirige ensuite vers la destination finale dans le réseau distant.
{% endhint %}

![](https://academy.hackthebox.com/storage/modules/158/22.png)

<mark style="color:green;">**Enabling Dynamic Port Forwarding with SSH**</mark>

```shell-session
ssh -D 9050 ubuntu@10.129.202.64
```

L’argument `-D` d’SSH active le **port forwarding dynamique**. Pour en tirer parti, on utilise **proxychains**, un outil qui redirige le trafic TCP via des proxys (SOCKS4/5, TOR, HTTP/HTTPS), permettant même d’enchaîner plusieurs proxys et de masquer l’IP de l’hôte source. Pour que proxychains utilise le port **9050**, il faut l’indiquer dans sa configuration (`/etc/proxychains.conf)`

<mark style="color:green;">**Checking /etc/proxychains.conf**</mark>

```shell-session
tail -4 /etc/proxychains.conf
```

<mark style="color:green;">**Using Nmap with Proxychains**</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200
```

Cette étape de transfert de ton trafic Nmap via **proxychains** vers un serveur distant s’appelle le **tunneling SOCKS**. Il faut utiliser uniquement des scans TCP complets, car proxychains ne gère pas les paquets partiels. Les vérifications de disponibilité des hôtes peuvent échouer sur Windows à cause du pare-feu qui bloque les pings. Les scans sur de larges plages prennent beaucoup de temps, donc on se concentre sur des hôtes individuels ou de petits sous-réseaux connus comme actifs, ici par exemple le Windows host 172.16.5.19.

{% hint style="info" %}
**Nmap envoie ses paquets** → **Interceptés par Proxychains** → **Envoyés via SOCKS5 (port 9050)** → **Transmis via SSH vers l’hôte pivot (10.129.202.64)** → **Puis redirigés vers la vraie cible (10.10.10.10)**.
{% endhint %}

<mark style="color:green;">**Enumerating the Windows Target through Proxychains**</mark>

```shell-session
proxychains nmap -v -Pn -sT 172.16.5.19
```

***

### <mark style="color:red;">Using Metasploit with Proxychains</mark>

```shell-session
mrroboteLiot@htb[/htb]$ proxychains msfconsole
```

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

<mark style="color:green;">**Using xfreerdp with Proxychains**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
{% endcode %}

<mark style="color:green;">**Successful RDP Pivot**</mark>

![RDP Pivot](https://academy.hackthebox.com/storage/modules/158/proxychaining.png)
