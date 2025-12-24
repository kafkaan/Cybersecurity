# Kerberos, DNS, LDAP, MSRPC



Bien que les systèmes d'exploitation Windows utilisent une variété de protocoles pour communiquer, Active Directory nécessite spécifiquement le protocole&#x20;

* <mark style="color:orange;">**LDAP**</mark> (Lightweight Directory Access Protocol)
* La version Microsoft de <mark style="color:orange;">**Kerberos**</mark>
* Le <mark style="color:orange;">**DNS**</mark> pour l'authentification et la communication ainsi que&#x20;
* <mark style="color:orange;">**MSRPC**</mark> qui est l'implémentation Microsoft de l'appel de procédure distante (RPC), une technique de communication entre processus utilisée pour les applications basées sur le modèle client-serveur.

***

### <mark style="color:blue;">Kerberos</mark>

Kerberos est le protocole d'authentification par défaut pour les comptes de domaine depuis Windows 2000.&#x20;

Kerberos est une norme ouverte qui permet l'interopérabilité avec d'autres systèmes utilisant la même norme. Lorsqu'un utilisateur se connecte à son PC, Kerberos est utilisé pour l'authentifier via une authentification mutuelle, c'est-à-dire que l'utilisateur et le serveur vérifient tous deux leur identité.&#x20;

Kerberos est un protocole d'authentification sans état basé sur des tickets plutôt que sur la transmission de mots de passe utilisateur sur le réseau.&#x20;

Dans le cadre des services de domaine Active Directory (AD DS), les contrôleurs de domaine disposent d'un centre de distribution de clés Kerberos (KDC) qui émet des tickets.&#x20;

Lorsqu'un utilisateur initie une demande de connexion à un système, le client qu'il utilise pour s'authentifier demande un ticket au KDC, en chiffrant la demande avec le mot de passe de l'utilisateur. Si le KDC peut déchiffrer la demande (AS-REQ) en utilisant leur mot de passe, il créera un ticket d'attribution de ticket (TGT) et le transmettra à l'utilisateur.&#x20;

L'utilisateur présente ensuite son TGT à un contrôleur de domaine pour demander un ticket de service d'attribution de ticket (TGS), chiffré avec le hash du mot de passe NTLM du service associé. Enfin, le client demande l'accès au service requis en présentant le TGS à l'application ou au service, qui le déchiffre avec son hash de mot de passe. Si l'ensemble du processus se déroule correctement, l'utilisateur sera autorisé à accéder au service ou à l'application demandé.

L'authentification Kerberos découple efficacement les identifiants des utilisateurs de leurs demandes de ressources consommables, en garantissant que leur mot de passe n'est pas transmis sur le réseau (par exemple, lors de l'accès à un site intranet SharePoint interne). Le centre de distribution de clés Kerberos (KDC) n'enregistre pas les transactions précédentes. Au lieu de cela, le ticket de service d'attribution de ticket Kerberos (TGS) s'appuie sur un ticket d'attribution de ticket (TGT) valide. Il suppose que si l'utilisateur possède un TGT valide, il a dû prouver son identité.

***

#### <mark style="color:blue;">Processus d'authentification Kerberos</mark>

{% stepper %}
{% step %}
<mark style="color:green;">**Demande initiale (AS-REQ)**</mark>

Lorsqu'un utilisateur se connecte, son mot de passe est utilisé pour chiffrer un horodatage, qui est envoyé au centre de distribution de clés (KDC) pour vérifier l'intégrité de l'authentification en le déchiffrant. Le KDC émet alors un ticket d'attribution de ticket (TGT), en le chiffrant avec la clé secrète du compte krbtgt. Ce TGT est utilisé pour demander des tickets de service pour accéder aux ressources réseau, permettant l'authentification sans transmettre de manière répétée les identifiants de l'utilisateur.
{% endstep %}

{% step %}
<mark style="color:green;">**Vérification du KDC**</mark>

Le service KDC sur le contrôleur de domaine vérifie la demande de service d'authentification (AS-REQ), vérifie les informations de l'utilisateur et crée un ticket d'attribution de ticket (TGT), qui est remis à l'utilisateur.
{% endstep %}

{% step %}
<mark style="color:green;">**Demande de TGS (TGS-REQ)**</mark>

Le TGS est chiffré avec le hash du mot de passe NTLM du compte de service ou d'ordinateur dans le contexte duquel l'instance de service s'exécute et est remis à l'utilisateur.
{% endstep %}

{% step %}
<mark style="color:green;">**Réponse TGS (TGS-REP)**</mark>

Le TGS est chiffré avec le hash du mot de passe NTLM du compte de service ou d'ordinateur dans le contexte duquel l'instance de service s'exécute et est remis à l'utilisateur.
{% endstep %}

{% step %}
<mark style="color:green;">**Accès au service (AP-REQ)**</mark>

L'utilisateur présente le TGS au service, et s'il est valide, l'utilisateur est autorisé à se connecter à la ressource.
{% endstep %}
{% endstepper %}

<figure><img src="../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Le protocole Kerberos utilise le port 88 (TCP et UDP). Lors de l'énumération d'un environnement Active Directory, nous pouvons souvent localiser les contrôleurs de domaine en effectuant des analyses de ports à la recherche du port 88 ouvert à l'aide d'un outil tel que Nmap.
{% endhint %}

***

### <mark style="color:blue;">DNS</mark>

Les services de domaine Active Directory (AD DS) utilisent le DNS pour permettre aux clients (postes de travail, serveurs et autres systèmes qui communiquent avec le domaine) de localiser les contrôleurs de domaine et pour que les contrôleurs de domaine hébergeant le service d'annuaire communiquent entre eux.&#x20;

Le DNS est utilisé pour résoudre les noms d'hôtes en adresses IP et est largement utilisé sur les réseaux internes et sur Internet.&#x20;

Les réseaux internes privés utilisent les espaces de noms DNS Active Directory pour faciliter les communications entre les serveurs, les clients et les pairs.

AD maintient une base de données de services s'exécutant sur le réseau sous forme d'enregistrements de service (SRV).&#x20;

Ces enregistrements de service permettent aux clients dans un environnement AD de localiser les services dont ils ont besoin, tels qu'un serveur de fichiers, une imprimante ou un contrôleur de domaine.

Le DNS dynamique est utilisé pour apporter automatiquement des modifications dans la base de données DNS si l'adresse IP d'un système change. Effectuer ces entrées manuellement prendrait beaucoup de temps et laisserait place à l'erreur.&#x20;

Si la base de données DNS ne dispose pas de l'adresse IP correcte pour un hôte, les clients ne pourront pas le localiser et communiquer avec lui sur le réseau.&#x20;

Lorsqu'un client rejoint le réseau, il localise le contrôleur de domaine en envoyant une requête au service DNS, en récupérant un enregistrement SRV de la base de données DNS et en transmettant le nom d'hôte du contrôleur de domaine au client. Le client utilise ensuite ce nom d'hôte pour obtenir l'adresse IP du contrôleur de domaine. Le DNS utilise les ports TCP et UDP 53. Le port UDP 53 est la valeur par défaut, mais il bascule vers TCP lorsqu'il ne peut plus communiquer et que les messages DNS dépassent 512 octets.

<figure><img src="../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:green;">Recherche DNS directe</mark>

```
PS C:\htb> nslookup INLANEFREIGHT.LOCAL

Server:  172.16.6.5
Address:  172.16.6.5

Name:    INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

#### <mark style="color:green;">Recherche DNS inversée</mark>

```
PS C:\htb> nslookup 172.16.6.5

Server:  172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

#### <mark style="color:green;">Recherche d'adresse IP d'un hôte</mark>

Si nous souhaitons trouver l'adresse IP d'un seul hôte, nous pouvons le faire en sens inverse, avec ou sans spécifier le FQDN :

```
PS C:\htb> nslookup ACADEMY-EA-DC01

Server:   172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

***

### <mark style="color:blue;">LDAP</mark>

Active Directory prend en charge le protocole LDAP (Lightweight Directory Access Protocol) pour les recherches d'annuaire.&#x20;

{% hint style="info" %}
LDAP est un protocole open source et multiplateforme utilisé pour l'authentification auprès de divers services d'annuaire (tels qu'AD). La dernière spécification LDAP est la version 3, publiée sous le nom de RFC 4511. Une bonne compréhension du fonctionnement de LDAP dans un environnement AD est cruciale pour les attaquants et les défenseurs. LDAP utilise le port 389, et LDAP sur SSL (LDAPS) communique via le port 636.
{% endhint %}

AD stocke les informations de compte utilisateur et les informations de sécurité telles que les mots de passe et facilite le partage de ces informations avec d'autres appareils sur le réseau.&#x20;

LDAP est le langage que les applications utilisent pour communiquer avec d'autres serveurs qui fournissent des services d'annuaire. En d'autres termes, LDAP est la façon dont les systèmes de l'environnement réseau peuvent "parler" à AD.

Une session LDAP commence par se connecter d'abord à un serveur LDAP, également connu sous le nom d'agent de système d'annuaire. Le contrôleur de domaine dans AD écoute activement les demandes LDAP, telles que les demandes d'authentification de sécurité.

La relation entre AD et LDAP peut être comparée à Apache et HTTP. De la même manière qu'Apache est un serveur web qui utilise le protocole HTTP, Active Directory est un serveur d'annuaire qui utilise le protocole LDAP.

Bien que rare, vous pouvez rencontrer une organisation lors d'une évaluation qui n'a pas AD mais utilise LDAP, ce qui signifie qu'elle utilise probablement un autre type de serveur LDAP tel qu'OpenLDAP.

***

#### <mark style="color:green;">Authentification AD LDAP</mark>

LDAP est configuré pour authentifier les identifiants auprès d'AD en utilisant une opération "BIND" pour définir l'état d'authentification d'une session LDAP. Il existe deux types d'authentification LDAP :

**Authentification simple** : Cela inclut l'authentification anonyme, l'authentification non authentifiée et l'authentification par nom d'utilisateur/mot de passe. L'authentification simple signifie qu'un nom d'utilisateur et un mot de passe créent une demande BIND pour s'authentifier auprès du serveur LDAP.

**Authentification SASL** : Le framework SASL (Simple Authentication and Security Layer) utilise d'autres services d'authentification, tels que Kerberos, pour se lier au serveur LDAP, puis utilise ce service d'authentification (Kerberos dans cet exemple) pour s'authentifier auprès de LDAP. Le serveur LDAP utilise le protocole LDAP pour envoyer un message LDAP au service d'autorisation, qui initie une série de messages de défi/réponse aboutissant à une authentification réussie ou non. SASL peut fournir une sécurité supplémentaire en raison de la séparation des méthodes d'authentification des protocoles d'application.

Les messages d'authentification LDAP sont envoyés en texte clair par défaut, de sorte que n'importe qui peut intercepter les messages LDAP sur le réseau interne. Il est recommandé d'utiliser le chiffrement TLS ou similaire pour protéger ces informations en transit.

<figure><img src="../../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">MSRPC</mark>

Comme mentionné ci-dessus, MSRPC est l'implémentation Microsoft de l'appel de procédure distante (RPC), une technique de communication entre processus utilisée pour les applications basées sur le modèle client-serveur. Les systèmes Windows utilisent MSRPC pour accéder aux systèmes dans Active Directory en utilisant quatre interfaces RPC clés.

#### <mark style="color:green;">Interfaces RPC principales</mark>

**lsarpc** : Un ensemble d'appels RPC vers le système LSA (Local Security Authority) qui gère la politique de sécurité locale sur un ordinateur, contrôle la politique d'audit et fournit des services d'authentification interactive. LSARPC est utilisé pour effectuer la gestion des politiques de sécurité du domaine.

**netlogon** : Netlogon est un processus Windows utilisé pour authentifier les utilisateurs et autres services dans l'environnement de domaine. C'est un service qui s'exécute en permanence en arrière-plan.

**samr** : Le SAM distant (samr) fournit des fonctionnalités de gestion pour la base de données de comptes de domaine, stockant des informations sur les utilisateurs et les groupes. Les administrateurs informatiques utilisent le protocole pour gérer les utilisateurs, les groupes et les ordinateurs en permettant aux administrateurs de créer, lire, mettre à jour et supprimer des informations sur les principes de sécurité.&#x20;

Les attaquants (et les pentesters) peuvent utiliser le protocole samr pour effectuer une reconnaissance sur le domaine interne en utilisant des outils tels que BloodHound pour cartographier visuellement le réseau AD et créer des "chemins d'attaque" pour illustrer visuellement comment l'accès administratif ou la compromission complète du domaine pourrait être atteint. Les organisations peuvent se protéger contre ce type de reconnaissance en modifiant une clé de registre Windows pour permettre uniquement aux administrateurs d'effectuer des requêtes SAM distantes, car par défaut, tous les utilisateurs de domaine authentifiés peuvent effectuer ces requêtes pour recueillir une quantité considérable d'informations sur le domaine AD.

**drsuapi** : drsuapi est l'API Microsoft qui implémente le protocole distant DRS (Directory Replication Service) utilisé pour effectuer des tâches liées à la réplication entre les contrôleurs de domaine dans un environnement multi-DC. Les attaquants peuvent utiliser drsuapi pour créer une copie du fichier de base de données du domaine Active Directory (NTDS.dit) afin de récupérer les hashs de mot de passe pour tous les comptes du domaine, qui peuvent ensuite être utilisés pour effectuer des attaques Pass-the-Hash pour accéder à plus de systèmes ou craqués hors ligne à l'aide d'un outil tel que Hashcat pour obtenir le mot de passe en clair afin de se connecter aux systèmes à l'aide de protocoles de gestion à distance tels que Bureau à distance (RDP) et WinRM.

***
