# Pivoting, Tunneling, and Port Forwarding

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
👉 **Le pivoting** permet de **franchir des barrières réseau via un hôte compromis** pour découvrir de nouvelles cibles.

<mark style="color:green;">**💡 Termes associés au pivoting :**</mark>

* **Pivot Host**
* **Proxy**
* **Foothold**
* **Jump Host**

L’objectif du pivoting est de **contourner la segmentation réseau**. À ne pas confondre avec le **tunneling**, qui encapsule le trafic réseau dans un autre protocole pour masquer son contenu (comme un VPN).

<mark style="color:green;">📌</mark> <mark style="color:green;"></mark><mark style="color:green;">**Différence avec le Lateral Movement**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

* **Lateral Movement** : Se déplacer entre plusieurs machines sur un même réseau pour élargir l’accès et escalader les privilèges.
* **Pivoting** : Utiliser un hôte compromis pour franchir des barrières réseau et atteindre des zones inaccessibles.
* **Tunneling** : Cacher ou chiffrer le trafic pour éviter la détection.
{% endhint %}

***

## <mark style="color:red;">Comparaison entre</mark> <mark style="color:red;"></mark><mark style="color:red;">**Lateral Movement**</mark><mark style="color:red;">,</mark> <mark style="color:red;"></mark><mark style="color:red;">**Pivoting**</mark> <mark style="color:red;"></mark><mark style="color:red;">et</mark> <mark style="color:red;"></mark><mark style="color:red;">**Tunneling**</mark>

<mark style="color:green;">**Lateral Movement**</mark>

Le **Lateral Movement** peut être décrit comme une technique permettant d'étendre notre accès à d'autres hôtes, applications et services au sein d'un environnement réseau.

***

<mark style="color:green;">**Pivoting**</mark>

Utilisation de plusieurs hôtes pour franchir des **frontières réseau** que nous ne pourrions normalement pas traverser.

Le pivoting a un **objectif ciblé** : il nous permet d'approfondir notre progression dans un réseau en **compromettant des hôtes spécifiques** ou des éléments d'infrastructure.

Un exemple concret de **Pivoting** :

***

<mark style="color:green;">**Tunneling**</mark>

Nous nous retrouvons souvent à utiliser divers protocoles pour **acheminer du trafic** à l’intérieur et à l’extérieur d’un réseau où il y a un risque de détection.

Par exemple, utiliser **HTTP** pour masquer notre trafic de **Command & Control (C2)** entre un serveur que nous possédons et un hôte compromis.

L’élément clé du tunneling est **l’obfuscation** de nos actions afin **d’éviter la détection** le plus longtemps possible.

Nous utilisons souvent des protocoles sécurisés comme **HTTPS sur TLS** ou **SSH encapsulé dans d'autres protocoles**.

***

## <mark style="color:red;">The Networking Behind Pivoting</mark>

#### <mark style="color:green;">Adressage IP & Cartes Réseau (NICs)</mark>

Tout ordinateur qui communique sur un réseau a besoin d'une adresse IP. Sans cela, il n'est pas connecté au réseau. L'adresse IP est attribuée par logiciel et est généralement obtenue automatiquement à partir d'un serveur DHCP.&#x20;

Il est également courant de voir des ordinateurs avec des adresses IP attribuées statiquement. L'attribution statique d'IP est courante pour :

* Les serveurs
* Les routeurs
* Les interfaces virtuelles des commutateurs
* Les imprimantes
* Et tout appareil fournissant des services critiques au réseau

Qu'elle soit attribuée dynamiquement ou statiquement, l'adresse IP est affectée à un **Network Interface Controller (NIC)**.&#x20;

Couramment, le NIC est appelé **carte réseau** ou **adaptateur réseau**.&#x20;

Un ordinateur peut avoir plusieurs NICs (physiques et virtuels), ce qui signifie qu'il peut avoir plusieurs adresses IP assignées, lui permettant de communiquer sur différents réseaux. Identifier les opportunités de pivoting dépend souvent des adresses IP attribuées aux machines compromises, car elles indiquent les réseaux accessibles par ces machines. C'est pourquoi il est important de toujours vérifier la présence de NICs supplémentaires avec des commandes comme `ifconfig` (macOS et Linux) et `ipconfig` (Windows).

#### <mark style="color:green;">Utilisation de</mark> <mark style="color:green;"></mark><mark style="color:green;">`ifconfig`</mark>

```
ifconfig
```

Le VPN chiffre le trafic et établit un tunnel sur un réseau public (souvent Internet), à travers une traduction d'adresses réseau (NAT) sur un équipement réseau public, et vers le réseau interne/privé.

{% hint style="warning" %}
N'oubliez pas que le NAT est couramment utilisé pour traduire des adresses IP privées en adresses IP publiques.
{% endhint %}

#### <mark style="color:green;">Utilisation de</mark> <mark style="color:green;"></mark><mark style="color:green;">`ipconfig`</mark>

```
ipconfig
```

Chaque adresse IPv4 est accompagnée d'un **masque de sous-réseau**. Si une adresse IP est comme un numéro de téléphone, le masque de sous-réseau est comme un indicatif régional. Il définit la partie **réseau** et la partie **hôte** d'une adresse IP. Lorsque le trafic réseau est destiné à une adresse IP située dans un autre réseau, l'ordinateur envoie ce trafic à sa **passerelle par défaut**.

#### <mark style="color:green;">Routage</mark>

Il est courant d'associer un routeur à un appareil qui connecte un réseau à Internet, mais **n'importe quel ordinateur peut devenir un routeur** et participer au routage.

Un routeur est défini par la présence d'une **table de routage**, qui lui permet d'acheminer le trafic en fonction de l'adresse IP de destination.

```
netstat -r
```
