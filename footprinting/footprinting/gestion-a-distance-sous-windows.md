# Gestion à Distance sous Windows

## <mark style="color:red;">Introduction</mark>

La gestion à distance des serveurs Windows est une fonctionnalité essentielle pour les administrateurs système.&#x20;

Elle permet de contrôler et de configurer les serveurs sans nécessiter un accès physique direct.&#x20;

Les principales technologies utilisées pour la gestion à distance sont&#x20;

* le **Remote Desktop Protocol (RDP)**
* **Windows Remote Management (WinRM)**
* **Windows Management Instrumentation (WMI)**.&#x20;

Ces outils sont intégrés dans Windows et permettent une gestion efficace et sécurisée des serveurs à distance.

***

## <mark style="color:red;">Remote Desktop Protocol (RDP)</mark>

### <mark style="color:blue;">**Présentation**</mark>

Le **Remote Desktop Protocol (RDP)** est un protocole développé par Microsoft pour permettre l'accès à distance à un ordinateur exécutant le système d'exploitation Windows. Ce protocole transmet les commandes d'affichage et de contrôle via une interface graphique (GUI) cryptée sur des réseaux IP.

RDP fonctionne au niveau de la couche application dans le modèle de référence TCP/IP, utilisant généralement <mark style="color:yellow;">**le port TCP 3389**</mark> comme protocole de transport. Il peut également utiliser le protocole UDP sur le même port pour l'administration à distance.

***

### <mark style="color:blue;">**Configuration**</mark>

Pour établir une session RDP, il est nécessaire que le pare-feu du réseau et celui du serveur autorisent les connexions externes. Si le serveur est situé derrière un routeur avec **Network Address Translation (NAT)**, il est indispensable d'utiliser l'adresse IP publique du serveur et de configurer un **port forwarding** sur le routeur NAT pour rediriger les connexions vers le serveur.

Depuis Windows Vista, RDP prend en charge **Transport Layer Security (TLS/SSL)**, ce qui signifie que toutes les données, y compris le processus de connexion, sont protégées par un bon niveau de chiffrement. Cependant, certains systèmes Windows peuvent accepter un chiffrement insuffisant via **RDP Security**, rendant ainsi la connexion vulnérable à des attaques potentielles.

Vulnérabilité dans le protocole RDP (Remote Desktop Protocol), même lorsqu'il utilise une sécurité basée sur des certificats. Voici une explication simplifiée :

1. **Certificats auto-signés** : Par défaut, les certificats utilisés pour vérifier l'identité d'un serveur RDP sont souvent auto-signés. Cela signifie que le certificat n'a pas été validé par une autorité de certification (CA) reconnue, mais plutôt créé et signé par le propre serveur.
2. **Problème pour le client** : Lorsque le client (l'utilisateur qui se connecte à distance) reçoit un tel certificat, il ne peut pas vérifier si le certificat est authentique ou s'il a été falsifié par un attaquant. Le client reçoit alors un avertissement, mais cet avertissement n'empêche pas nécessairement la connexion.
3. **Vulnérabilité** : En raison de cette situation, un attaquant pourrait créer un faux certificat qui ressemble à celui du serveur légitime. Le client ne pourrait pas faire la différence, ce qui laisse la porte ouverte à des attaques, même si un avertissement est affiché.

Ce service peut être activé via le **Gestionnaire de serveur** et est configuré par défaut pour n’accepter les connexions que depuis des hôtes utilisant **l’authentification au niveau réseau (NLA)**.

***

### <mark style="color:blue;">**Analyse de la Sécurité RDP**</mark>

**Nmap** est un outil puissant pour scanner et recueillir des informations sur un service RDP. Voici un exemple de commande Nmap pour scanner un serveur RDP :

```bash
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
```

Cette commande permet de déterminer si **Network Level Authentication (NLA)** est activée, de récupérer la version du produit, et d'obtenir des informations sur le nom d'hôte.

```bash
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
| rdp-ntlm-info: 
|   Target_Name: ILF-SQL-01
|   NetBIOS_Domain_Name: ILF-SQL-01
|   NetBIOS_Computer_Name: ILF-SQL-01
|   DNS_Domain_Name: ILF-SQL-01
|   DNS_Computer_Name: ILF-SQL-01
|   Product_Version: 10.0.17763
|_  System_Time: 2021-11-06T13:46:00+00:00
```

Cette analyse montre que NLA est activée et que les informations telles que le nom de l'ordinateur et la version du produit sont accessibles.

Pour inspecter manuellement le contenu des paquets, la commande suivante peut être utilisée :

```bash
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```

Cette commande fournit un traçage détaillé des paquets, utile pour identifier les cookies RDP et d'autres éléments qui peuvent être détectés par des systèmes de sécurité.

***

### <mark style="color:blue;">**Outils pour Vérifier la Sécurité RDP**</mark>

Un script Perl, **rdp-sec-check.pl**, développé par Cisco CX Security Labs, peut être utilisé pour identifier de manière non authentifiée les paramètres de sécurité des serveurs RDP en fonction des handshakes.

Installation du script :

```bash
sudo cpan
```

Après l'installation des modules Perl nécessaires, le script peut être cloné et exécuté :

{% code title="Cpan" overflow="wrap" %}
```bash
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```
{% endcode %}

Ce script vérifie la prise en charge des protocoles et les méthodes de chiffrement utilisées par le serveur RDP cible.

***

### <mark style="color:blue;">Connexion RDP avec</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`xfreerdp`</mark>

Sous Linux, on peut utiliser `xfreerdp` pour se connecter à un serveur RDP et interagir avec l'interface graphique du serveur :

```bash
xfreerdp /u:nom_utilisateur /p:"mot_de_passe" /v:adresse_ip_serveur
```

Exemple :

```bash
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

***

## <mark style="color:red;">**WinRM**</mark>&#x20;

Le Windows Remote Management (WinRM) est un protocole de gestion à distance intégré à Windows, basé sur la ligne de commande.&#x20;

WinRM utilise le protocole **SOAP (Simple Object Access Protocol)** pour établir des connexions avec des hôtes distants et leurs applications.&#x20;

Par conséquent, WinRM doit être explicitement activé et configuré à partir de Windows 10.&#x20;

<mark style="color:orange;">**WinRM repose sur les ports TCP 5985 et 5986**</mark> pour la communication, le dernier **port 5986 utilisant HTTPS**, car les ports 80 et 443 étaient auparavant utilisés pour cette tâche. Cependant, comme le port 80 était principalement bloqué pour des raisons de sécurité, les nouveaux ports 5985 et 5986 sont utilisés aujourd'hui.

Un autre composant adapté à WinRM pour l'administration est le Windows Remote Shell (WinRS), qui permet d'exécuter des commandes arbitraires sur le système distant. Ce programme est même inclus par défaut sur Windows 7. Ainsi, avec WinRM, il est possible d'exécuter une commande à distance sur un autre serveur.

Des services comme les sessions à distance utilisant PowerShell et la fusion des journaux d'événements nécessitent WinRM. Il est activé par défaut à partir de la version Windows Server 2012, mais il doit d'abord être configuré pour les versions antérieures de serveurs et les clients, et les exceptions de pare-feu nécessaires doivent être créées.

<mark style="color:green;">**Cartographie du service**</mark>&#x20;

Comme nous le savons déjà, WinRM utilise par défaut les ports TCP 5985 (HTTP) et 5986 (HTTPS), que nous pouvons scanner en utilisant Nmap. Cependant, il est souvent observé que seul le HTTP (TCP 5985) est utilisé au lieu du HTTPS (TCP 5986).

<mark style="color:green;">**Nmap WinRM**</mark>

{% code title="" overflow="wrap" %}
```bash
mrroboteLiot@htb[/htb]$ nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```
{% endcode %}

Si nous voulons savoir si un ou plusieurs serveurs distants peuvent être atteints via WinRM, nous pouvons facilement le faire avec l'aide de PowerShell. Le cmdlet **Test-WsMan** est responsable de cette tâche, et le nom de l'hôte en question lui est transmis. Dans les environnements basés sur Linux, nous pouvons utiliser un outil appelé **evil-winrm**, un autre outil de test de pénétration conçu pour interagir avec WinRM.

<mark style="color:green;">**Exemple d'utilisation d'evil-winrm**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

{% code title="" overflow="wrap" %}
```bash
mrroboteLiot@htb[/htb]$ evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```
{% endcode %}

***

## <mark style="color:red;">**WMI**</mark>&#x20;

* **WMI (Windows Management Instrumentation)** est l’implémentation de Microsoft du **Common Information Model (CIM)** et une extension du standard **WBEM** pour Windows.
* Permet l’accès **en lecture et en écriture** à presque tous les paramètres des systèmes Windows.
* Constitue **l’interface principale** pour l’administration et la maintenance à distance des ordinateurs Windows (PC et serveurs).
* Accessible via **PowerShell**, **VBScript** ou la console **WMIC**.
* WMI n’est pas un seul programme, mais un ensemble de **programmes et de bases de données** (référentiels).

<mark style="color:green;">**Cartographie du service**</mark>&#x20;

L'initialisation de la communication WMI se fait toujours sur le port TCP 135, et après l'établissement réussi de la connexion, la communication est déplacée vers un port aléatoire. Par exemple, le programme **wmiexec.py** de l'outil Impacket peut être utilisé pour cela.

<mark style="color:green;">**Exemple d'utilisation de WMIexec.py**</mark> <mark style="color:green;"></mark><mark style="color:green;">:</mark>

{% code title="" overflow="wrap" %}
```bash
mrroboteLiot@htb[/htb]$ /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
ILF-SQL-01
```
{% endcode %}
