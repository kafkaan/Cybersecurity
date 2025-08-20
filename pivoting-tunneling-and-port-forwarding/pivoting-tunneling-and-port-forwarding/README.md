# Pivoting, Tunneling, and Port Forwarding

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

Lors d’un test d’intrusion ou d’une mission Red Team, il arrive que nous ayons compromis des identifiants, clés SSH ou jetons d’accès, mais sans pouvoir atteindre directement un autre hôte. Dans ce cas, nous devons utiliser un **hôte pivot**, déjà compromis, pour accéder à d’autres segments réseau.

Dès que nous accédons à un nouvel hôte, il est essentiel de vérifier **notre niveau de privilège, les connexions réseau et la présence de VPN ou logiciels d’accès distant**. Si l’hôte possède plusieurs cartes réseau, nous pouvons potentiellement l’utiliser pour atteindre d’autres segments.

👉 **Le pivoting** permet de **franchir des barrières réseau via un hôte compromis** pour découvrir de nouvelles cibles.

💡 Termes associés au pivoting :

* **Pivot Host**
* **Proxy**
* **Foothold**
* **Jump Host**

L’objectif du pivoting est de **contourner la segmentation réseau**. À ne pas confondre avec le **tunneling**, qui encapsule le trafic réseau dans un autre protocole pour masquer son contenu (comme un VPN).

📌 **Différence avec le Lateral Movement** :

* **Lateral Movement** : Se déplacer entre plusieurs machines sur un même réseau pour élargir l’accès et escalader les privilèges.
* **Pivoting** : Utiliser un hôte compromis pour franchir des barrières réseau et atteindre des zones inaccessibles.
* **Tunneling** : Cacher ou chiffrer le trafic pour éviter la détection.

***

## <mark style="color:red;">Comparaison entre</mark> <mark style="color:red;"></mark><mark style="color:red;">**Lateral Movement**</mark><mark style="color:red;">,</mark> <mark style="color:red;"></mark><mark style="color:red;">**Pivoting**</mark> <mark style="color:red;"></mark><mark style="color:red;">et</mark> <mark style="color:red;"></mark><mark style="color:red;">**Tunneling**</mark>

<mark style="color:green;">**Lateral Movement**</mark>

Le **Lateral Movement** peut être décrit comme une technique permettant d'étendre notre accès à d'autres hôtes, applications et services au sein d'un environnement réseau.

Le Lateral Movement peut également nous aider à accéder à des ressources de domaine spécifiques dont nous pourrions avoir besoin pour élever nos privilèges.

Il permet souvent **l'escalade de privilèges** entre les hôtes.

En plus de cette explication, nous pouvons aussi étudier la manière dont d'autres organisations reconnues décrivent le **Lateral Movement**. Voici deux explications à consulter lorsque nous avons du temps :

* **Explication de Palo Alto Networks**
* **Explication de MITRE**

Un exemple concret de **Lateral Movement** :

> Lors d'une évaluation, nous avons obtenu un accès initial à l'environnement cible et avons pris le contrôle du compte administrateur local.\
> Nous avons effectué un scan réseau et trouvé trois autres hôtes Windows sur le réseau.\
> Nous avons tenté d'utiliser les mêmes identifiants administrateurs locaux, et l'un des appareils partageait le même compte administrateur.\
> Nous avons donc utilisé ces identifiants pour nous déplacer latéralement vers cet autre appareil, ce qui nous a permis de **compromettre davantage le domaine**.

***

<mark style="color:green;">**Pivoting**</mark>

Utilisation de plusieurs hôtes pour franchir des **frontières réseau** que nous ne pourrions normalement pas traverser.

Le pivoting a un **objectif ciblé** : il nous permet d'approfondir notre progression dans un réseau en **compromettant des hôtes spécifiques** ou des éléments d'infrastructure.

Un exemple concret de **Pivoting** :

> Lors d'un engagement difficile, la cible avait segmenté son réseau **physiquement et logiquement**.\
> Cette séparation rendait notre progression difficile et nous empêchait d’atteindre nos objectifs.\
> Nous avons donc exploré le réseau et compromis un hôte qui s’est avéré être une **station de travail d’ingénierie** utilisée pour surveiller et gérer des équipements dans l’environnement opérationnel.\
> Cet hôte était **doublement connecté** (**dual-homed**) avec **plusieurs cartes réseau reliées à différents segments**.\
> Sans son accès aux réseaux **entreprise** et **opérationnel**, nous n’aurions pas pu pivoter et atteindre notre objectif.

***

<mark style="color:green;">**Tunneling**</mark>

Nous nous retrouvons souvent à utiliser divers protocoles pour **acheminer du trafic** à l’intérieur et à l’extérieur d’un réseau où il y a un risque de détection.

Par exemple, utiliser **HTTP** pour masquer notre trafic de **Command & Control (C2)** entre un serveur que nous possédons et un hôte compromis.

L’élément clé du tunneling est **l’obfuscation** de nos actions afin **d’éviter la détection** le plus longtemps possible.

Nous utilisons souvent des protocoles sécurisés comme **HTTPS sur TLS** ou **SSH encapsulé dans d'autres protocoles**.

Ces techniques permettent aussi des tactiques comme **l’exfiltration de données** hors d’un réseau cible, ou **la livraison de nouveaux payloads** et instructions dans le réseau.

Un exemple concret de **Tunneling** :

> Une façon dont nous avons utilisé le tunneling était de **cacher notre trafic dans HTTP et HTTPS**.\
> C'est une technique courante pour maintenir un **C2 (Command and Control)** sur les hôtes compromis.\
> Nous avons **dissimulé nos commandes** dans des requêtes **GET et POST** qui semblaient être du trafic normal.\
> Pour un œil non entraîné, cela ressemblait à des requêtes classiques sur un site web.\
> Si le paquet était correctement formé, il était transmis à notre **serveur de contrôle**.\
> Sinon, il était redirigé vers un autre site web, potentiellement **déjouant les défenseurs** qui tenteraient de l’analyser.

***

#### <mark style="color:green;">**Résumé**</mark>

Nous devons considérer ces tactiques comme des concepts distincts :

* **Lateral Movement** : permet de **s’étendre latéralement** dans un réseau et d’**escalader les privilèges**.
* **Pivoting** : permet d'**aller plus en profondeur** dans un réseau en accédant à des environnements auparavant inaccessibles.
* **Tunneling** : permet d'**encapsuler le trafic** pour masquer nos actions et **éviter la détection**.

***

## <mark style="color:red;">The Networking Behind Pivoting</mark>

Comprendre le concept du pivoting suffisamment bien pour l'utiliser efficacement lors d'un engagement nécessite une bonne compréhension de certains concepts réseau fondamentaux. Cette section est une rapide révision des concepts réseau essentiels pour comprendre le pivoting.

#### <mark style="color:green;">Adressage IP & Cartes Réseau (NICs)</mark>

Tout ordinateur qui communique sur un réseau a besoin d'une adresse IP. Sans cela, il n'est pas connecté au réseau. L'adresse IP est attribuée par logiciel et est généralement obtenue automatiquement à partir d'un serveur DHCP. Il est également courant de voir des ordinateurs avec des adresses IP attribuées statiquement. L'attribution statique d'IP est courante pour :

* Les serveurs
* Les routeurs
* Les interfaces virtuelles des commutateurs
* Les imprimantes
* Et tout appareil fournissant des services critiques au réseau

Qu'elle soit attribuée dynamiquement ou statiquement, l'adresse IP est affectée à un **Network Interface Controller (NIC)**. Couramment, le NIC est appelé **carte réseau** ou **adaptateur réseau**. Un ordinateur peut avoir plusieurs NICs (physiques et virtuels), ce qui signifie qu'il peut avoir plusieurs adresses IP assignées, lui permettant de communiquer sur différents réseaux. Identifier les opportunités de pivoting dépend souvent des adresses IP attribuées aux machines compromises, car elles indiquent les réseaux accessibles par ces machines. C'est pourquoi il est important de toujours vérifier la présence de NICs supplémentaires avec des commandes comme `ifconfig` (macOS et Linux) et `ipconfig` (Windows).

#### <mark style="color:green;">Utilisation de</mark> <mark style="color:green;"></mark><mark style="color:green;">`ifconfig`</mark>

```
mrroboteLiot@htb[/htb]$ ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        ...
```

Dans la sortie ci-dessus, chaque NIC est identifié (eth0, eth1, lo, tun0) avec les informations d'adressage et les statistiques de trafic. **L'interface tunnel `tun0` indique qu'une connexion VPN est active**. Lorsque nous nous connectons à l'un des serveurs VPN de HTB via Pwnbox ou notre machine d'attaque, une interface de tunnel est toujours créée et une adresse IP lui est attribuée.

Le VPN chiffre le trafic et établit un tunnel sur un réseau public (souvent Internet), à travers une traduction d'adresses réseau (NAT) sur un équipement réseau public, et vers le réseau interne/privé.

Remarquez les adresses IP attribuées à chaque NIC. L'adresse attribuée à `eth0` (134.122.100.200) est une adresse IP publique, ce qui signifie que les fournisseurs d'accès Internet (FAI) acheminent le trafic provenant de cette IP sur Internet. En revanche, les autres NICs ont des adresses IP privées, routables uniquement au sein du réseau interne.

N'oubliez pas que le NAT est couramment utilisé pour traduire des adresses IP privées en adresses IP publiques.

#### <mark style="color:green;">Utilisation de</mark> <mark style="color:green;"></mark><mark style="color:green;">`ipconfig`</mark>

```
PS C:\Users\htb-student> ipconfig

Windows IP Configuration

Unknown adapter NordLynx:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1a9
   IPv4 Address. . . . . . . . . . . : 10.129.221.36
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:df81%8
                                       10.129.0.1
```

La sortie ci-dessus provient de l'exécution de `ipconfig` sur un système Windows. Nous voyons que ce système a plusieurs adaptateurs, mais un seul d'entre eux a des adresses IP attribuées. On y trouve des adresses IPv6 et une adresse IPv4.

Chaque adresse IPv4 est accompagnée d'un **masque de sous-réseau**. Si une adresse IP est comme un numéro de téléphone, le masque de sous-réseau est comme un indicatif régional. Il définit la partie **réseau** et la partie **hôte** d'une adresse IP. Lorsque le trafic réseau est destiné à une adresse IP située dans un autre réseau, l'ordinateur envoie ce trafic à sa **passerelle par défaut**.

#### <mark style="color:green;">Routage</mark>

Il est courant d'associer un routeur à un appareil qui connecte un réseau à Internet, mais **n'importe quel ordinateur peut devenir un routeur** et participer au routage.

Certaines des techniques abordées ici requièrent qu'un hôte pivot fasse transiter du trafic vers un autre réseau. L'un des moyens d'y parvenir est d'utiliser **AutoRoute**, qui permet à notre machine d'attaque d'obtenir des routes vers des réseaux cibles accessibles via un hôte pivot.

Un routeur est défini par la présence d'une **table de routage**, qui lui permet d'acheminer le trafic en fonction de l'adresse IP de destination.

Examinons la table de routage sur une machine Pwnbox en utilisant `netstat -r` ou `ip route`.

#### Table de routage sur Pwnbox

```
mrroboteLiot@htb[/htb]$ netstat -r

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         178.62.64.1     0.0.0.0         UG        0 0          0 eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG        0 0          0 tun0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.106.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
178.62.64.0     0.0.0.0         255.255.192.0   U         0 0          0 eth0
```

Cette sortie montre comment les différents réseaux et passerelles sont configurés pour router le trafic.

Dans les sections suivantes, nous verrons comment exploiter ces concepts pour effectuer du pivoting et accéder à des réseaux internes via des hôtes compromis.
