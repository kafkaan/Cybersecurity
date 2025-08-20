---
description: >-
  Enumeration is the most critical part of all. The art, the difficulty, and the
  goal are not to gain access to our target computer. Instead, it is identifying
  all of the ways we could attack a target w
cover: >-
  https://png.pngtree.com/thumb_back/fh260/background/20230702/pngtree-d-rendering-of-an-internet-page-featuring-login-credentials-input-fields-image_3740977.jpg
coverY: 58
---

# NMAP

## <mark style="color:red;">Introduction de Nmap</mark>

> Network Mapper (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua. It is designed to scan networks and identify which hosts are available on the network using raw packets, and services and applications, including the name and version, where possible.

### <mark style="color:blue;">Syntax</mark>

```shell
mrroboteLiot@htb[/htb]$ nmap <scan types> <options> <target>

```

***

## <mark style="color:red;">Host Discovery</mark>

{% hint style="info" %}
<mark style="color:orange;">**TTL (Time To Live**</mark><mark style="color:orange;">)</mark> est une valeur de minuterie incluse dans les paquets envoyés sur les réseaux qui indique au destinataire pendant combien de temps conserver ou utiliser le paquet avant de le supprimer et d'expirer les données (paquet). Les valeurs TTL sont différentes pour différents systèmes d'exploitation. Ainsi, vous pouvez déterminer le système d'exploitation en fonction de la valeur TTL. Vous pouvez obtenir la valeur TTL en envoyant une requête ping à une adresse.&#x20;

* Linux : 64
* Windows : 128
* Solaris : 255
* Cisco routers/switches : 255
{% endhint %}

Lors de tests de pénétration internes pour l'ensemble du réseau d'une entreprise, il est crucial de d'abord obtenir un aperçu des systèmes en ligne avec lesquels nous pouvons travailler.

La méthode la plus efficace consiste à utiliser des **requêtes ICMP echo.**

{% hint style="warning" %}
L’ICMP est un protocole que les périphériques d’un réseau utilisent pour communiquer les problèmes de transmission de données. Dans cette définition du protocole ICMP, l’une des principales façons de l’utiliser est de déterminer si les données atteignent leur destination et ce au bon moment. Cela fait de l’ICMP un facteur important du processus de signalement des erreurs et des tests visant à déterminer si un réseau transmet bien les données. Cependant, il peut également être utilisé pour exécuter des attaques par déni de service distribué (DDoS).
{% endhint %}

### <mark style="color:blue;">**Scan de Plage d'Adresses**</mark>&#x20;

```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

```

* **10.129.2.0/24** : Plage d'adresses cible.
* **-sn** : Désactive le scan de ports.
* **-oA tnet** : Stocke les résultats dans tous les formats avec le nom 'tnet'.

***

### <mark style="color:blue;">**Scan à Partir d'une Liste d'IP**</mark>

{% code title="Nmap" overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```
{% endcode %}

* **-iL** : Effectue les scans définis sur les cibles de la liste 'hosts.lst'.

### <mark style="color:blue;">Scan de Multiples IPs</mark>

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```
{% endcode %}

* **10.129.2.18-20** : Spécifie la plage d'adresses dans l'octet respectif.

### <mark style="color:blue;">Scan d'une IP Unique</mark>

```bash
sudo nmap 10.129.2.18 -sn -oA host
```

* **10.129.2.18** : Adresse IP cible.
* **-oA host** : Stocke les résultats dans tous les formats avec le nom 'host'.

{% hint style="warning" %}
If we disable port scan (`-sn`), Nmap automatically **ping scan with `ICMP Echo`**` ``Requests` (`-PE`). Once such a request is sent, we usually expect an `ICMP reply` if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an `ARP ping` resulting in an `ARP reply`. We can confirm this with the "`--packet-trace`" option. To ensure that ICMP echo requests are sent, we also define the option (`-PE`) for this.

{% code overflow="wrap" lineNumbers="true" fullWidth="true" %}
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
```
{% endcode %}
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th width="198"></th><th></th></tr></thead><tbody><tr><td><code>10.129.2.18</code></td><td>Performs defined scans against the target.</td></tr><tr><td><code>-sn</code></td><td>Disables port scanning.</td></tr><tr><td><code>-oA host</code></td><td>Stores the results in all formats starting with the name 'host'.</td></tr><tr><td><code>-PE</code></td><td>Performs the ping scan by using 'ICMP Echo requests' against the target.</td></tr><tr><td><code>--packet-trace</code></td><td>Shows all packets sent and received</td></tr></tbody></table>

Another way to determine why Nmap has our target marked as "alive" is with the "`--reason`" option.

{% code lineNumbers="true" %}
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --reason 
```
{% endcode %}

To disable ARP requests and scan our target with the desired `ICMP echo requests`, we can disable ARP pings by setting the "`--disable-arp-ping`" option.&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```
{% endcode %}

***

## <mark style="color:red;">Host and Port Scanning</mark>

After we have found out that our target is alive, we want to get a more accurate picture of the system. The information we need includes:

* **Open ports and its services**
* **Service versions**
* <mark style="color:orange;">I</mark>**nformation that the services provided**
* **Operating system**

There are a total of 6 different states for a scanned port we can obtain:

<table data-header-hidden data-full-width="true"><thead><tr><th width="203"></th><th></th></tr></thead><tbody><tr><td><strong>State</strong></td><td><strong>Description</strong></td></tr><tr><td><code>open</code></td><td>This indicates that the connection to the scanned port has been established. These connections can be <strong>TCP connections</strong>, <strong>UDP datagrams</strong> as well as <strong>SCTP associations</strong>.</td></tr><tr><td><code>closed</code></td><td>When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an <code>RST</code> flag. This scanning method can also be used to determine if our target is alive or not.</td></tr><tr><td><code>filtered</code></td><td>Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.</td></tr><tr><td><code>unfiltered</code></td><td>This state of a port only occurs during the <strong>TCP-ACK</strong> scan and means that the port is accessible, but it cannot be determined whether it is open or closed.</td></tr><tr><td><code>open|filtered</code></td><td>If we do not get a response for a specific port, <code>Nmap</code> will set it to that state. This indicates that a firewall or packet filter may protect the port.</td></tr><tr><td><code>closed|filtered</code></td><td>This state only occurs in the <strong>IP ID idle</strong> scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.</td></tr></tbody></table>

&#x20;<mark style="color:orange;">💡</mark> <mark style="color:orange;"></mark><mark style="color:orange;">**TCP SYN Scan  (**</mark><mark style="color:orange;">**`-sS`**</mark><mark style="color:orange;">**)**</mark>

```
 - Sends a TCP packet with SYN flag set
 - If a SYN/ACK (or SYN) is received --> Port is Open, TCP initiation accepted
 - If a RST is received --> Port is closed
 - If no response is received --> Port is considered filtered
 - If a ICMP Unreachable is received --> Port is considered filtered

```

<mark style="color:orange;">**UDP Scans (**</mark><mark style="color:orange;">**`-sU`**</mark><mark style="color:orange;">**)**</mark>

```
 - Nmap sends a UDP Packet to the specified ports
 - If an ICMP Port Unreachable comes back --> Port is closed
 - Other ICMP Unreachable errors --> Port is filtered
 - Server responds with UDP packet --> Port is opened
 - No response after retransmission --> Port is Open|Filtered

```

And a counter example that could produce different results than `-sS`:

<mark style="color:orange;">**TCP ACK Scan (**</mark><mark style="color:orange;">**`-sA`**</mark><mark style="color:orange;">**)**</mark>

{% code overflow="wrap" %}
```
This scan never determines OPEN or OPEN|Filtered:

 - A packet is sent with only the ACK flag
 - If a System is unfiltered, both Open and Closed ports will both return RST flagged packets
 - Ports that don't respond, or send ICMP Errors are labeled Filtered.


```
{% endcode %}

### <mark style="color:blue;">Discovering Open TCP Ports</mark>

`Nmap` scans the top 1000 TCP ports with the SYN scan (`-sS`). This SYN scan is set only to default when we run it as root because of the socket permissions required to create raw TCP packets. Otherwise, the TCP scan (`-sT`) is performed by default.

We can define the ports one by one (-p 22,25,80,139,445), by range (-p 22-445), by top ports (--top-ports=10) or -p-&#x20;

<mark style="color:orange;">**Scanning Top 10 TCP Ports**</mark>

```bash
sudo nmap 10.129.2.28 --top-ports=10 
```

{% hint style="info" %}
To have a clear view of the SYN scan, we disable the ICMP echo requests <mark style="color:red;">`(-Pn)`</mark>, DNS resolution `(-n),` and `ARP ping scan`` `<mark style="color:red;">`(--disable-arp-ping)`</mark>.
{% endhint %}

<mark style="color:orange;">**Nmap - Trace the Packets**</mark>

{% code title="Trace the Packets" overflow="wrap" lineNumbers="true" %}
```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```
{% endcode %}

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Message</strong></td><td><strong>Description</strong></td></tr><tr><td><code>SENT (0.0429s)</code></td><td>Indicates the SENT operation of Nmap, which sends a packet to the target.</td></tr><tr><td><code>TCP</code></td><td>Shows the protocol that is being used to interact with the target port.</td></tr><tr><td><code>10.10.14.2:63090 ></code></td><td>Represents our IPv4 address and the source port, which will be used by Nmap to send the packets.</td></tr><tr><td><code>10.129.2.28:21</code></td><td>Shows the target IPv4 address and the target port.</td></tr><tr><td><code>S</code></td><td>SYN flag of the sent TCP packet.</td></tr><tr><td><code>ttl=56 id=57322 iplen=44 seq=1699105818 win=1024 mss 1460</code></td><td>Additional TCP Header parameters.</td></tr></tbody></table>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Message</strong></td><td><strong>Description</strong></td></tr><tr><td><code>RCVD (0.0573s)</code></td><td>Indicates a received packet from the target.</td></tr><tr><td><code>TCP</code></td><td>Shows the protocol that is being used.</td></tr><tr><td><code>10.129.2.28:21 ></code></td><td>Represents targets IPv4 address and the source port, which will be used to reply.</td></tr><tr><td><code>10.10.14.2:63090</code></td><td>Shows our IPv4 address and the port that will be replied to.</td></tr><tr><td><code>RA</code></td><td>RST and ACK flags of the sent TCP packet.</td></tr><tr><td><code>ttl=64 id=0 iplen=40 seq=0 win=0</code></td><td>Additional TCP Header parameters.</td></tr></tbody></table>

#### <mark style="color:orange;">**Connect Scan**</mark>

> The Nmap [TCP Connect Scan](https://nmap.org/book/scan-methods-connect-scan.html) (`-sT`) uses the TCP three-way handshake to determine if a specific port on a target host is open or closed. The scan sends an `SYN` packet to the target port and waits for a response. It is considered open if the target port responds with an `SYN-ACK` packet and closed if it responds with an `RST` packet.

{% code title="Connect Scan on TCP Port 443" overflow="wrap" lineNumbers="true" fullWidth="true" %}
```bash
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```
{% endcode %}

***

### <mark style="color:blue;">Ports Filtrés avec Nmap</mark>

<mark style="color:green;">**Concept des Ports Filtrés**</mark>

* **Ports Filtrés** : Un port est indiqué comme filtré lorsque les paquets envoyés n'obtiennent pas de réponse ou sont rejetés par un firewall.
* **Paquets Droppés** : Nmap ne reçoit aucune réponse. Par défaut, Nmap renvoie la requête une fois (--max-retries=1) pour vérifier si le paquet précédent n'a pas été mal géré.
* **Paquets Rejetés** : La cible renvoie un message ICMP indiquant que le port est inaccessible.

<mark style="color:green;">**Exemple de Paquets Droppés**</mark>

```bash
sudo nmap 10.129.2.28 -p 139 --packet-trace -n --disable-arp-ping -Pn
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Paquet Envoyé</strong></td><td><strong>Paquet Reçu</strong></td></tr><tr><td>SENT (0.0381s) TCP 10.10.14.2:60277 > 10.129.2.28:139 S ttl=47 id=14523 iplen=44 seq=4175236769 win=1024 &#x3C;mss 1460></td><td>(Aucun paquet reçu, car les paquets sont droppés par le firewall)</td></tr><tr><td>SENT (1.0411s) TCP 10.10.14.2:60278 > 10.129.2.28:139 S ttl=45 id=7372 iplen=44 seq=4175171232 win=1024 &#x3C;mss 1460></td><td>(Aucun paquet reçu, car les paquets sont droppés par le firewall)</td></tr></tbody></table>

| **Résumé**                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------- |
| Le port 139 est filtré, car les paquets SYN envoyés n'ont pas reçu de réponse, ce qui indique que le firewall a droppé les paquets. |

<mark style="color:green;">**Exemple de Paquets Rejetés**</mark>

```bash
sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn
```

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Paquet Envoyé</strong></td><td><strong>Paquet Reçu</strong></td></tr><tr><td>SENT (0.0388s) TCP 10.129.2.28:52472 > 10.129.2.28:445 S ttl=49 id=21763 iplen=44 seq=1418633433 win=1024 &#x3C;mss 1460></td><td>RCVD (0.0487s) ICMP [10.129.2.28 > 10.129.2.28 Port 445 unreachable (type=3/code=3) ] IP [ttl=64 id=20998 iplen=72]</td></tr></tbody></table>

| **Résumé**                                                                                                                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Le port 445 est filtré, car un paquet ICMP de type 3 (port unreachable) a été reçu, indiquant que le firewall rejette les paquets envoyés à ce port. |

***

### <mark style="color:blue;">Discovering Open UDP Ports</mark>

{% hint style="info" %}
<mark style="color:orange;">**`UDP`**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**is a**</mark><mark style="color:orange;">**&#x20;**</mark><mark style="color:orange;">**`stateless protocol`**</mark> and does not require a three-way handshake like TCP. We do not receive any acknowledgment. Consequently, the timeout is much longer, making the whole `UDP scan` (`-sU`) much slower than the `TCP scan` (`-sS`).
{% endhint %}

#### <mark style="color:orange;">**UDP Port Scan**</mark>

```bash
 sudo nmap 10.129.2.28 -F -sU
```

| `-F`  | Scans top 100 ports. |
| ----- | -------------------- |
| `-sU` | Performs a UDP scan. |

{% hint style="info" %}
If we get an ICMP response with `error code 3` (port unreachable), we know that the port is indeed `closed`.

For all other ICMP responses, the scanned ports are marked as (`open|filtered`).\

{% endhint %}

***

## <mark style="color:red;">Service Enumeration</mark>

### <mark style="color:blue;">Service Version Detection</mark>

```bash
sudo nmap 10.129.2.28 -p- -sV
```

{% hint style="warning" %}
option <mark style="color:orange;">`(--stats-every=5s)`</mark> that we can use is defining how periods of time the status should be shown. Here we can specify the number of seconds (`s`) or minutes (`m`), after which we want to get the status.

We can also increase the `verbosity level` <mark style="color:red;">`(-v / -vv)`</mark>`,` which will show us the open ports directly when `Nmap` detects them.
{% endhint %}

### <mark style="color:blue;">Banner Grabbing</mark>

{% hint style="danger" %}
Primarily, `Nmap` looks at the banners of the scanned ports and prints them out. If it cannot identify versions through the banners, `Nmap` attempts to identify them through a signature-based matching system, but this significantly increases the scan's duration. One disadvantage to `Nmap`'s presented results is that the automatic scan can miss some information because sometimes `Nmap` does not know how to handle it. Let us look at an example of this.

**Identification par Signatures :** Si Nmap ne parvient pas à identifier la version d'un service uniquement par la bannière, il utilise un système de correspondance basé sur les signatures. Ce système :

* **Compare les Réponses :** Compare les réponses des ports scannés avec une base de données de signatures connues (patterns) pour identifier le service et sa version.
* **Augmente la Durée du Scan :** Ce processus est plus complexe et prend plus de temps, car il nécessite l'exécution de plusieurs probes (sondages) et l'analyse approfondie des réponses.
{% endhint %}

{% code title="nmap" overflow="wrap" %}
```bash
mrroboteLiot@htb[/htb]$ sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 20:10 CEST
<SNIP>
NSOCK INFO [0.4200s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 18 [10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)..
Service scan match (Probe NULL matched with NULL line 3104): 10.129.2.28:25 is smtp.  Version: |Postfix smtpd|||
NSOCK INFO [0.4200s] nsock_iod_delete(): nsock_iod_delete (IOD #1)
Nmap scan report for 10.129.2.28
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
Service Info: Host:  inlane
```
{% endcode %}

we can see the port's status, service name, and hostname. Nevertheless, let us look at this line here:

* `NSOCK INFO [0.4200s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 18 [10.129.2.28:25] (35 bytes): 220 inlane ESMTP Postfix (Ubuntu)..`
* &#x20;It happens because, after a successful three-way handshake, the server often sends a banner for identification. This serves to let the client know which service it is working with. At the network level, this happens with a `PSH` flag in the TCP header

<mark style="color:orange;">**Tcpdump**</mark>

```wasm
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

#### <mark style="color:orange;">Nc</mark>

```bash
nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```

***

## <mark style="color:red;">Nmap Scripting Engine</mark>

### <mark style="color:blue;">**Introduction**</mark>

Le **Nmap Scripting Engine (NSE)** permet d'écrire et d'exécuter des scripts en Lua pour étendre les fonctionnalités de Nmap. Les scripts NSE peuvent effectuer diverses tâches, allant de la découverte de services à l'évaluation des vulnérabilités.

**Catégories de Scripts NSE**

1. **auth** : Détermine les informations d'authentification.
2. **broadcast** : Découverte des hôtes par diffusion.
3. **brute** : Brute force pour les tentatives de connexion.
4. **default** : Scripts par défaut exécutés avec `-sC`.
5. **discovery** : Évaluation des services accessibles.
6. **dos** : Vérification des vulnérabilités aux dénis de service.
7. **exploit** : Exploite les vulnérabilités connues.
8. **external** : Utilisation de services externes.
9. **fuzzer** : Identifie les vulnérabilités en envoyant des paquets variés.
10. **intrusive** : Scripts potentiellement nuisibles pour le système cible.
11. **malware** : Détecte les malwares.
12. **safe** : Scripts non intrusifs et non destructifs.
13. **version** : Détection des versions des services.
14. **vuln** : Identification des vulnérabilités spécifiques.

### <mark style="color:blue;">**Commandes de Base**</mark>

1.  **Scripts par Défaut**

    ```bash
    sudo nmap <target> -sC
    ```

    * **-sC** : Exécute les scripts par défaut.
2.  **Scripts par Catégorie**

    <pre class="language-bash"><code class="lang-bash"><strong>sudo nmap &#x3C;target> --script &#x3C;category>
    </strong></code></pre>

    * **\<category>** : Spécifie la catégorie de scripts.
3.  **Scripts Définis**

    ```bash
    sudo nmap <target> --script <script-name>,<script-name>,...
    ```

    * **\<script-name>** : Liste des scripts spécifiques à utiliser.

**Exemples Pratiques**

1.  **Scan avec Scripts Spécifiques**

    ```bash
    sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
    ```

    * **banner** : Affiche la bannière du service.
    * **smtp-commands** : Affiche les commandes SMTP supportées.
2.  **Scan Aggressif**

    ```bash
    sudo nmap 10.129.2.28 -p 80 -A
    ```

    * **-A** : Détection des services, du système d'exploitation, traceroute, et exécution des scripts par défaut.
3.  **Évaluation des Vulnérabilités**

    ```bash
    sudo nmap 10.129.2.28 -p 80 -sV --script vuln
    ```

    * **-sV** : Détection des versions des services.
    * **--script vuln** : Exécute les scripts de la catégorie vulnérabilités.

**Ressources Supplémentaires**

* [Nmap NSE Documentation](https://nmap.org/nsedoc/index.html) : Pour plus d'informations sur les scripts et catégories disponibles.

***

## <mark style="color:red;">**Performance et Optimisation des Scans Nmap**</mark>

Optimiser les performances des scans avec Nmap est crucial pour effectuer des analyses efficaces sur des réseaux étendus ou avec une bande passante limitée. Les paramètres de performance permettent d'ajuster la vitesse des scans, les délais de réponse, et la fréquence des paquets envoyés.

***

### <mark style="color:blue;">**1. Options de Performance**</mark>

* **Vitesse de Scan (-T <0-5>)**
  * Définit la rapidité du scan.
  * **-T 0** : Paranoïaque (très lent, minimum de détection).
  * **-T 1** : Discret.
  * **-T 2** : Poli.
  * **-T 3** : Normal (défaut).
  * **-T 4** : Aggressif.
  * **-T 5** : Insane (très rapide, risque élevé de détection).
* **Parallélisme (--min-parallelism \<number>)**
  * Définit le nombre minimal de threads pour les connexions simultanées.
* **Timeouts**
  * **--initial-rtt-timeout \<time>** : Temps initial de réponse du paquet.
  * **--max-rtt-timeout \<time>** : Temps maximal de réponse du paquet.
  *   Exemples :

      ```bash
      sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
      ```
* **Taux de Paquets (--min-rate \<number>)**
  * Nombre de paquets envoyés par seconde.
  *   Exemples :

      <pre class="language-bash"><code class="lang-bash"><strong>sudo nmap 10.129.2.0/24 -F --min-rate 300
      </strong></code></pre>
* **Retries (--max-retries \<number>)**
  * Nombre de tentatives en cas de non-réponse.
  *   Exemple :

      ```bash
      sudo nmap 10.129.2.0/24 -F --max-retries 0
      ```

***

### <mark style="color:blue;">**2. Exemples de Performance**</mark>

*   **Scan par Défaut**

    ```bash
    sudo nmap 10.129.2.0/24 -F
    ```

    * Trouvé : 10 hôtes en 39.44 secondes.
*   **Optimisation du Timeout**

    {% code title="Optimisation" overflow="wrap" %}
    ```bash
    sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
    ```
    {% endcode %}

    * Trouvé : 8 hôtes en 12.29 secondes.
    * Conclusion : Un timeout trop court peut faire manquer des hôtes.
*   **Réduire les Retries**

    ```bash
    sudo nmap 10.129.2.0/24 -F --max-retries 0
    ```

    * Par défaut : 23 ports ouverts trouvés.
    * Réduit les retries : 21 ports ouverts trouvés.
    * Conclusion : Moins de retries peuvent faire manquer des informations importantes.
*   **Optimiser le Taux de Paquets**

    ```bash
    sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
    ```

    * Temps de scan réduit à 8.67 secondes (contre 29.83 secondes).
    * Les ports ouverts restent les mêmes : 23.
* **Timing Templates**
  *   **Scan Normal**

      ```bash
      sudo nmap 10.129.2.0/24 -F -oN tnet.default
      ```

      * Temps de scan : 32.44 secondes.
  *   **Scan Insane**

      ```bash
      desudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
      ```

      * Temps de scan : 18.07 secondes.

{% embed url="https://academy.hackthebox.com/module/19/section/105" %}

***

## <mark style="color:red;">Firewall and IDS/IPS Evasion</mark>

### <mark style="color:blue;">**1. Introduction**</mark>

Nmap offre plusieurs méthodes pour contourner les règles de pare-feu et les systèmes IDS/IPS. Ces méthodes incluent la fragmentation des paquets, l'utilisation de fausses adresses IP, et d'autres techniques. Voici un résumé des principales techniques et concepts abordés :

### <mark style="color:blue;">**2. Pare-feux (Firewalls)**</mark>

* **Définition** : Un pare-feu est un système de sécurité qui surveille le trafic réseau entrant et sortant en fonction de règles prédéfinies. Il peut permettre, bloquer ou ignorer les paquets de données.
* **Fonctionnement** : Les paquets peuvent être soit **drop** (abandonnés sans réponse), soit **reject** (rejetés avec un drapeau RST et des codes ICMP comme "Port Unreachable", "Host Unreachable", etc.).

### <mark style="color:blue;">**3. IDS/IPS**</mark>

* **IDS (Système de Détection d'Intrusions)** : Analyse le réseau à la recherche d'attaques potentielles, les signale et informe les administrateurs.
* **IPS (Système de Prévention d'Intrusions)** : Prend des mesures automatiques pour empêcher les attaques détectées par l'IDS.

{% hint style="warning" %}
The packets can either be `dropped`, or `rejected`. The `dropped` packets are ignored, and no response is returned from the host.

This is different for `rejected` packets that are returned with an `RST` flag. These packets contain different types of ICMP error codes or contain nothing at all.

Such errors can be:

* Net Unreachable
* Net Prohibited
* Host Unreachable
* Host Prohibited
* Port Unreachable
* Proto Unreachable
{% endhint %}

### <mark style="color:blue;">**4. Méthodes de Scan pour Contourner les Pare-feux et IDS/IPS**</mark>

{% hint style="info" %}
One method to determine whether such `IPS system` is present in the target network is to scan from a single host (`VPS`). If at any time this host is blocked and has no access to the target network, we know that the administrator has taken some security measures. Accordingly, we can continue our penetration test with another `VPS`.
{% endhint %}

<mark style="color:yellow;">**4.1 SYN-Scan (**</mark><mark style="color:yellow;">**`-sS`**</mark><mark style="color:yellow;">**)**</mark>

* **Description** : Envoie des paquets SYN pour établir une connexion TCP. La réponse peut indiquer si un port est ouvert, fermé, ou filtré.
*   **Exemple de Commande** :

    ```bash
    sudo nmap -p 21,22,25 -sS <target>
    ```
* **Résultat Typique** : Réponse SYN-ACK pour les ports ouverts, RST pour les ports fermés, et absence de réponse pour les ports filtrés.

<mark style="color:yellow;">**4.2 ACK-Scan (**</mark><mark style="color:yellow;">**`-sA`**</mark><mark style="color:yellow;">**)**</mark>

* **Description** : Envoie des paquets ACK pour tester les règles de filtrage du pare-feu. Utile pour déterminer si un port est filtré ou non.
*   **Exemple de Commande** :

    ```bash
    sudo nmap -p 21,22,25 -sA <target>
    ```
* **Résultat Typique** : Réponse RST pour les ports ouverts, absence de réponse pour les ports filtrés.

<mark style="color:yellow;">**4.3 Décoy (**</mark><mark style="color:yellow;">**`-D`**</mark><mark style="color:yellow;">**)**</mark>

* **Description** : Utilise des adresses IP factices pour masquer l'origine des paquets envoyés.
*   **Exemple de Commande** :

    ```bash
    sudo nmap -p 80 -sS -D RND:5 <target>
    ```
* **Utilité** : Permet de contourner les filtres qui bloquent les adresses IP spécifiques ou les plages d'adresses.

### <mark style="color:blue;">**5. Techniques d'Evasion**</mark>

<mark style="color:yellow;">**5.1 Scan avec IP Source Spécifiée (**</mark><mark style="color:yellow;">**`-S`**</mark><mark style="color:yellow;">**)**</mark>

* **Description** : Scanne en utilisant une adresse IP source différente pour éviter les filtres basés sur l'adresse IP d'origine.
*   **Exemple de Commande** :

    ```bash
    sudo nmap -p 445 -S <source_ip> <target>
    ```

<mark style="color:yellow;">**5.2 Scan depuis un Port Source Spécifique (**</mark><mark style="color:yellow;">**`--source-port`**</mark><mark style="color:yellow;">**)**</mark>

* **Description** : Utilise un port source spécifique pour les paquets, ce qui peut aider à contourner certains filtres.
*   **Exemple de Commande** :

    ```bash
    sudo nmap -p 50000 --source-port 53 <target>
    ```

<mark style="color:yellow;">**5.3 DNS Proxying**</mark>

{% hint style="warning" %}
Par défaut, Nmap effectue une résolution DNS inversée, sauf indication contraire, afin de trouver des informations plus importantes sur notre cible. Ces requêtes DNS sont également transmises dans la plupart des cas, car le serveur web donné est censé être trouvé et visité. Les requêtes DNS sont effectuées via le port UDP 53. Le port TCP 53 était auparavant uniquement utilisé pour les soi-disant "transferts de zone" entre les serveurs DNS ou pour le transfert de données de plus de 512 octets. De plus en plus, cela change en raison des extensions IPv6 et DNSSEC. Ces changements entraînent la réalisation de nombreuses requêtes DNS via le port TCP 53.

Cependant, Nmap nous donne toujours un moyen de spécifier nous-mêmes les serveurs DNS (--dns-server \<ns>,\<ns>). Cette méthode pourrait nous être fondamentale si nous nous trouvons dans une zone démilitarisée (DMZ). Les serveurs DNS de l'entreprise sont généralement plus fiables que ceux d'Internet. Ainsi, par exemple, nous pourrions les utiliser pour interagir avec les hôtes du réseau interne. Comme autre exemple, nous pouvons utiliser le port TCP 53 comme port source (--source-port) pour nos analyses. Si l'administrateur utilise le pare-feu pour contrôler ce port et ne filtre pas correctement l'IDS/IPS, nos paquets TCP seront considérés comme fiables et passeront à travers.
{% endhint %}

* **Description** : Utilise des serveurs DNS internes pour effectuer des scans, ce qui peut contourner les filtres externes.
*   **Exemple de Commande** :

    ```bash
    sudo nmap --dns-server <dns1>,<dns2> <target>
    ```

### <mark style="color:blue;">**6. Exemples Pratiques**</mark>

*   **Scan SYN avec Paquets Filtrés** :

    ```bash
    sudo nmap -p 50000 -sS -Pn -n --disable-arp-ping --packet-trace
    ```
*   **Scan SYN depuis Port DNS** :

    {% code title="" overflow="wrap" %}
    ```bash
    sudo nmap -p 50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
    ```
    {% endcode %}
*   **Connexion à un Port Filtré avec Ncat** :

    ```bash
    ncat -nv --source-port 53 <target> 50000
    ```

***

## <mark style="color:red;">WALKTHROUGH</mark>

### <mark style="color:blue;">Lab - Easy</mark> <a href="#lab---easy" id="lab---easy"></a>

Now let’s get practical. A company hired us to test their IT security defenses, including their IDS and IPS systems. Our client wants to increase their IT security and will, therefore, make specific improvements to their IDS/IPS systems after each successful test. We do not know, however, according to which guidelines these changes will be made. Our goal is to find out specific information from the given situations.

We are only ever provided with a machine protected by IDS/IPS systems and can be tested. For learning purposes and to get a feel for how IDS/IPS can behave, we have access to a status web page at: http://TARGET\_IP/status.php

#### Questions <a href="#questions" id="questions"></a>

1. Our client wants to know if we can identify which operating system their provided machine is running on. Submit the OS name as the answer.

We know that they are running `http` on port `80` due to status page. It seems to keep count of how many IDS detentions there are, so we want to be stealthy during our enumeration process.

{% code fullWidth="true" %}
```bash
sudo nmap -sV 10.129.22.245 -Pn -p80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 23:00 EDT
Nmap scan report for 10.129.22.245
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 [Redacted]

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.36 seconds
```
{% endcode %}

The above does a service scan on port 80 while disabling ping probes.

Answer is: \[Redacted]

### <mark style="color:blue;">Lab - Medium</mark> <a href="#lab---medium" id="lab---medium"></a>

After we conducted the first test and submitted our results to our client, the administrators made some changes and improvements to the IDS/IPS and firewall. We could hear that the administrators were not satisfied with their previous configurations during the meeting, and they could see that the network traffic could be filtered more strictly.

**Questions**

1. After the configurations are transferred to the system, our client wants to know if it is possible to find out our target’s DNS server version. Submit the DNS server version of the target as the answer.

We know that `DNS` runs on port `53` and uses `UDP`, so we target that to reduce the amount of alerts their IDS will trigger

{% code fullWidth="true" %}
```bash
Sudo nmap -sV 10.129.22.22 -Pn -p53 -sU

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 23:02 EDT
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.129.22.22
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
53/udp open  domain  (unknown banner: [redacted]})
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.81 seconds
```
{% endcode %}

`-Pn` disables ICMP Echo Requests; `-sU` performs UDP scan.

The Version is revealed

### <mark style="color:blue;">Lab - Hard</mark> <a href="#lab---hard" id="lab---hard"></a>

With our second test’s help, our client was able to gain new insights and sent one of its administrators to a training course for IDS/IPS systems. As our client told us, the training would last one week. Now the administrator has taken all the necessary precautions and wants us to test this again because specific services must be changed, and the communication for the provided software had to be modified.

**Questions**

1. Now our client wants to know if it is possible to find out the version of the running services. Identify the version of service our client was talking about and submit the flag as the answer.

First we must find the ports open, checking to see if it accepts `TCP 53` source:

{% code fullWidth="true" %}
```bash
sudo nmap 10.129.2.47 -sS -Pn -n --disable-arp-ping --source-port 53 -p- -vvv

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 23:18 EDT                                         
Initiating SYN Stealth Scan at 23:18                                                                                 
Scanning 10.129.2.47 [65535 ports]                                                                                   
Discovered open port 80/tcp on 10.129.2.47                                                                           
Discovered open port 22/tcp on 10.129.2.47                                                                           
SYN Stealth Scan Timing: About 24.73% done; ETC: 23:20 (0:01:34 remaining)                                   
Stats: 0:00:43 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan                               
SYN Stealth Scan Timing: About 27.24% done; ETC: 23:21 (0:01:55 remaining)
Discovered open port 50000/tcp on 10.129.2.47
<SNIP>
```
{% endcode %}

We kill the scan when `50000` appears, as it is a non-standard port.

We run `-sV` to see if we can grab what is running on it:

{% code fullWidth="true" %}
```bash
sudo nmap 10.129.2.47 -sS -sV -Pn -n --disable-arp-ping --source-port 53 -p50000 -vvv                             

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-16 23:27 EDT                                                   
NSE: Loaded 46 scripts for scanning.                                                                                                                                                                                                       
Initiating SYN Stealth Scan at 23:27                                                                                 
Scanning 10.129.2.47 [1 port]                                                                                        
Completed SYN Stealth Scan at 23:27, 0.11s elapsed (1 total ports)                                                   
Initiating Service scan at 23:27                                                                                     
NSE: Script scanning 10.129.2.47.                                                                                    
NSE: Starting runlevel 1 (of 2) scan.                                                                                
Initiating NSE at 23:27                                                                                              
Completed NSE at 23:27, 0.00s elapsed                                                                                
NSE: Starting runlevel 2 (of 2) scan.                                                                                
Initiating NSE at 23:27                                                                                              
Completed NSE at 23:27, 0.00s elapsed                                                                                
Nmap scan report for 10.129.2.47                                                                                     
Host is up, received user-set (0.093s latency).                                                                      
Scanned at 2024-05-16 23:27:11 EDT for 0s                                                                            

PORT      STATE SERVICE    REASON         VERSION
50000/tcp open  tcpwrapped syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.55 seconds
           Raw packets sent: 1 (44B) | Rcvd: 1 (44B)                                                                                                             
```
{% endcode %}

Port `50000` is showing `open`, when targeted, but no flag.

We can try to connect to the port directly using netcat:

{% code fullWidth="true" %}
```bash
netcat -nv -p 53 10.129.2.47 50000

(UNKNOWN) [10.129.2.47] 50000 (?) open
220 [redacted]
421 Login timeout (300 seconds): closing control connection
```
{% endcode %}

`-p` defines source port

We have successfully identified the version!!
