# Attacking DNS

***

DNS c’est principalement udp sur le port 53 mais il utilisera de plus en plus tcp sur le port 53 avec le temps dns a toujours été conçu pour utiliser à la fois udp et tcp sur le port 53 depuis le début udp est utilisé par défaut et il bascule sur tcp quand udp ne suffit pas généralement quand la taille du paquet est trop grande pour passer en un seul paquet udp comme presque toutes les applications réseau utilisent dns les attaques contre les serveurs dns sont parmi les menaces les plus courantes et importantes aujourd’hui

***

### <mark style="color:blue;">Enumeration</mark>

```shell-session
mrroboteLiot@htb[/htb]# nmap -p53 -Pn -sV -sC 10.10.110.213

```

***

### <mark style="color:blue;">DNS Zone Transfer</mark>

une zone dns est une partie de l’espace de noms dns gérée par une organisation ou un administrateur spécifique comme le dns est composé de plusieurs zones dns les serveurs dns utilisent les transferts de zone dns pour copier une partie de leur base de données vers un autre serveur dns sauf si un serveur dns est correctement configuré pour limiter quelles adresses ip peuvent faire un transfert de zone dns n’importe qui peut demander une copie des informations de zone car les transferts de zone dns ne nécessitent aucune authentification en plus le service dns fonctionne généralement sur un port udp mais lors d’un transfert de zone dns il utilise un port tcp pour assurer une transmission fiable des données\
un attaquant peut exploiter cette vulnérabilité de transfert de zone dns pour en apprendre davantage sur l’espace de noms dns de l’organisation cible ce qui augmente la surface d’attaque pour exploiter cela on peut utiliser l’outil dig avec le type de requête dns axfr pour extraire tout l’espace de noms dns depuis un serveur dns vulnérable

#### <mark style="color:green;">**DIG - AXFR Zone Transfer**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```
{% endcode %}

Tools like [Fierce](https://github.com/mschwager/fierce) can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# fierce --domain zonetransfer.me
```
{% endcode %}

***

### <mark style="color:green;">Domain Takeovers & Subdomain Enumeration</mark>

la prise de contrôle de domaine consiste à enregistrer un nom de domaine inexistant pour prendre le contrôle d’un autre domaine si des attaquants trouvent un domaine expiré ils peuvent le réclamer pour mener d’autres attaques comme héberger du contenu malveillant sur un site web ou envoyer des e-mails de phishing en utilisant ce domaine récupéré\
la prise de contrôle est aussi possible avec des sous-domaines on parle alors de prise de contrôle de sous-domaine un enregistrement cname dans le dns est utilisé pour faire correspondre différents domaines à un domaine principal beaucoup d’organisations utilisent des services tiers comme aws github akamai fastly et d’autres cdn pour héberger leur contenu dans ce cas elles créent généralement un sous-domaine et le font pointer vers ces services par exemple,

```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

le nom de domaine par exemple sub.target.com utilise un enregistrement cname vers un autre domaine par exemple anotherdomain.com supposons que anotherdomain.com expire et qu’il soit disponible pour n’importe qui pour l’enregistrer étant donné que le serveur dns de target.com a toujours l’enregistrement cname alors toute personne qui enregistre anotherdomain.com prendra le contrôle complet de sub.target.com tant que l’enregistrement dns n’est pas mis à jour

#### <mark style="color:green;">**Subdomain Enumeration**</mark>

Before performing a subdomain takeover, we should enumerate subdomains for a target domain using tools like [Subfinder](https://github.com/projectdiscovery/subfinder). This tool can scrape subdomains from open sources like [DNSdumpster](https://dnsdumpster.com/). Other tools like [Sublist3r](https://github.com/aboul3la/Sublist3r) can also be used to brute-force subdomains by supplying a pre-generated wordlist:

{% code fullWidth="true" %}
```shell-session
mrroboteLiot@htb[/htb]# ./subfinder -d inlanefreight.com -v                  
```
{% endcode %}

An excellent alternative is a tool called [Subbrute](https://github.com/TheRook/subbrute). This tool allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access.

<mark style="color:green;">**Subbrute**</mark>

<pre class="language-shell-session" data-full-width="true"><code class="lang-shell-session"><strong>mrroboteLiot@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&#x26;1
</strong>mrroboteLiot@htb[/htb]$ cd subbrute
mrroboteLiot@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
mrroboteLiot@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
</code></pre>

Sometimes internal physical configurations are poorly secured, which we can exploit to upload our tools from a USB stick. Another scenario would be that we have reached an internal host through pivoting and want to work from there. Of course, there are other alternatives, but it does not hurt to know alternative ways and possibilities.

The tool has found four subdomains associated with `inlanefreight.com`. Using the `nslookup` or `host` command, we can enumerate the `CNAME` records for those subdomains.

```shell-session
mrroboteLiot@htb[/htb]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

The `support` subdomain has an alias record pointing to an AWS S3 bucket. However, the URL `https://support.inlanefreight.com` shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now, we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

![](https://academy.hackthebox.com/storage/modules/116/s3.png)

The [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository is also an excellent reference for a subdomain takeover vulnerability. It shows whether the target services are vulnerable to a subdomain takeover and provides guidelines on assessing the vulnerability.

***

### <mark style="color:blue;">DNS Spoofing</mark>

DNS spoofing is also referred to as DNS Cache Poisoning. This attack involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website. Example attack paths for the DNS Cache Poisoning are as follows:

* An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack.
* Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

#### <mark style="color:green;">**Local DNS Cache Poisoning**</mark>

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```shell-session
mrroboteLiot@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

![](https://academy.hackthebox.com/storage/modules/116/target.png)

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`:

![](https://academy.hackthebox.com/storage/modules/116/etter_plug.png)

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:

![](https://academy.hackthebox.com/storage/modules/116/etter_site.png)

In addition, a ping coming from the target IP address `192.168.152.129` to `inlanefreight.com` should be resolved to `192.168.225.110` as well:

```cmd-session
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```
