# Active Directory Objects

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Utilisateurs</mark>

Ce sont les utilisateurs au sein de l’environnement AD de l’organisation.\
Les utilisateurs sont considérés comme des **objets feuille**, ce qui signifie qu’ils ne peuvent pas contenir d’autres objets.

Un autre exemple d’objet feuille est une boîte aux lettres dans Microsoft Exchange.

Un objet utilisateur est considéré comme un **principal de sécurité** et possède un **identificateur de sécurité (SID)** et un **identifiant global unique (GUID)**.

Les objets utilisateur possèdent de nombreux attributs possibles, tels que le nom d’affichage, l’heure de dernière connexion, la date du dernier changement de mot de passe, l’adresse e-mail, la description du compte, le responsable, l’adresse, et plus encore.

***

### <mark style="color:blue;">Contacts</mark>

Un objet contact est généralement utilisé pour représenter un utilisateur externe et contient des attributs informationnels tels que le prénom, le nom, l’adresse e-mail, le numéro de téléphone, etc.

Ce sont des objets feuille et **ne sont PAS des principaux de sécurité** (objets sécurisables), ils ne possèdent donc pas de SID, seulement un GUID.\
Un exemple serait une fiche de contact pour un fournisseur tiers ou un client.

***

### <mark style="color:blue;">Imprimantes</mark>

Un objet imprimante pointe vers une imprimante accessible au sein du réseau AD.\
Comme un contact, une imprimante est un objet feuille et n’est pas un principal de sécurité, elle possède donc uniquement un GUID.

Les imprimantes ont des attributs tels que le nom de l’imprimante, les informations du pilote, le numéro de port, etc.

***

### <mark style="color:blue;">Ordinateurs</mark>

Un objet ordinateur est tout ordinateur joint au réseau AD (poste de travail ou serveur).\
Les ordinateurs sont des objets feuille car ils ne contiennent pas d’autres objets. Cependant, ils sont considérés comme des **principaux de sécurité** et possèdent un SID et un GUID.

Comme les utilisateurs, ils sont des **cibles privilégiées pour les attaquants**, car un accès administratif complet à un ordinateur (en tant que compte tout-puissant **NT AUTHORITY\SYSTEM**) accorde des droits similaires à ceux d’un utilisateur de domaine standard et peut être utilisé pour effectuer la majorité des tâches d’énumération qu’un compte utilisateur peut réaliser (à l’exception de quelques cas à travers les relations d’approbation entre domaines).

***

### <mark style="color:blue;">Dossiers partagés</mark>

Un objet dossier partagé pointe vers un dossier partagé sur l’ordinateur spécifique où se trouve le dossier.\
Les dossiers partagés peuvent avoir des contrôles d’accès stricts et peuvent être :

* accessibles à tout le monde (même sans compte AD valide),
* ouverts uniquement aux utilisateurs authentifiés (ce qui signifie que toute personne disposant du compte utilisateur le moins privilégié OU d’un compte ordinateur (**NT AUTHORITY\SYSTEM**) peut y accéder),
* ou verrouillés pour autoriser l’accès uniquement à certains utilisateurs/groupes.

Toute personne non explicitement autorisée se verra refuser la liste ou la lecture de son contenu.

Les dossiers partagés **ne sont PAS des principaux de sécurité** et possèdent uniquement un GUID.\
Les attributs d’un dossier partagé peuvent inclure le nom, l’emplacement sur le système et les droits d’accès de sécurité.

***

### <mark style="color:blue;">Groupes</mark>

Un groupe est considéré comme un **objet conteneur** car il peut contenir d’autres objets, y compris des utilisateurs, des ordinateurs et même d’autres groupes.

Un groupe est considéré comme un **principal de sécurité** et possède un SID et un GUID.

Dans AD, les groupes sont un moyen de gérer les autorisations des utilisateurs et l’accès à d’autres objets sécurisables (utilisateurs et ordinateurs).

Par exemple, si nous voulons donner à 20 utilisateurs du support informatique l’accès au groupe **Remote Management Users** sur un hôte de rebond, au lieu d’ajouter les utilisateurs un par un, nous pourrions ajouter le groupe, et les utilisateurs hériteraient des autorisations prévues via leur appartenance au groupe.

Dans Active Directory, nous voyons fréquemment ce que l’on appelle des **groupes imbriqués** (un groupe ajouté comme membre d’un autre groupe), ce qui peut conduire un ou plusieurs utilisateurs à obtenir des droits non intentionnels.

L’appartenance à des groupes imbriqués est quelque chose que nous observons et exploitons souvent lors des tests d’intrusion.\
L’outil **BloodHound** permet de découvrir les chemins d’attaque au sein d’un réseau et de les illustrer dans une interface graphique. Il est excellent pour auditer l’appartenance aux groupes et révéler les impacts parfois non intentionnels de l’imbrication des groupes.

Les groupes dans AD peuvent avoir de nombreux attributs, les plus courants étant le nom, la description, l’appartenance et les autres groupes auxquels le groupe appartient. De nombreux autres attributs peuvent être définis, que nous étudierons plus en détail plus tard dans ce module.

***

### <mark style="color:blue;">Unités d’organisation (OU)</mark>

Une unité d’organisation, ou **OU**, est un conteneur que les administrateurs systèmes peuvent utiliser pour stocker des objets similaires afin de faciliter l’administration.

Les OU sont souvent utilisées pour la **délégation administrative de tâches** sans accorder à un compte utilisateur des droits administratifUnités d’organisation (OU)s complets.

Par exemple, nous pouvons avoir une OU de niveau supérieur appelée _Employés_, puis des OU enfants pour les différents départements tels que Marketing, RH, Finance, Support informatique, etc.

Si un compte reçoit le droit de réinitialiser les mots de passe sur l’OU de niveau supérieur, cet utilisateur aura le droit de réinitialiser les mots de passe de tous les utilisateurs de l’entreprise.

Cependant, si la structure des OU est telle que les départements spécifiques sont des OU enfants de l’OU Support informatique, alors tout utilisateur placé dans l’OU Support informatique se verra déléguer ce droit s’il est accordé.

D’autres tâches pouvant être déléguées au niveau de l’OU incluent la création/suppression d’utilisateurs, la modification de l’appartenance aux groupes, la gestion des liens de stratégie de groupe et la réinitialisation des mots de passe.

Les OU sont très utiles pour gérer les paramètres de **Stratégie de Groupe (Group Policy)** à travers un sous-ensemble d’utilisateurs et de groupes dans un domaine.

Par exemple, nous pouvons vouloir définir une stratégie de mot de passe spécifique pour les comptes de service privilégiés. Ces comptes pourraient être placés dans une OU particulière et une GPO leur serait attribuée afin d’appliquer cette stratégie de mot de passe à tous les comptes qu’elle contient.

Quelques attributs d’une OU incluent son nom, ses membres, ses paramètres de sécurité, et plus encore.

***

### <mark style="color:blue;">Domaine</mark>

Un domaine est la structure d’un réseau AD.\
Les domaines contiennent des objets tels que des utilisateurs et des ordinateurs, qui sont organisés dans des objets conteneurs : groupes et OU.

Chaque domaine possède sa propre base de données et son propre ensemble de stratégies pouvant être appliquées à tout ou partie des objets du domaine.

Certaines stratégies sont définies par défaut (et peuvent être ajustées), telles que la stratégie de mot de passe du domaine. D’autres sont créées et appliquées selon les besoins de l’organisation, comme le blocage de l’accès à **cmd.exe** pour tous les utilisateurs non administratifs ou le mappage de lecteurs partagés lors de la connexion.

***

### <mark style="color:blue;">Contrôleurs de domaine</mark>

Les contrôleurs de domaine sont essentiellement le **cerveau d’un réseau AD**.\
Ils gèrent les demandes d’authentification, vérifient les utilisateurs sur le réseau et contrôlent qui peut accéder aux différentes ressources du domaine.

Toutes les demandes d’accès sont validées via le contrôleur de domaine et les demandes d’accès privilégié sont basées sur des rôles prédéterminés attribués aux utilisateurs.

Il applique également les stratégies de sécurité et stocke les informations concernant tous les autres objets du domaine.

***

### <mark style="color:blue;">Sites</mark>

Un site dans AD est un ensemble d’ordinateurs répartis sur un ou plusieurs sous-réseaux connectés via des liens à haut débit.\
Ils sont utilisés pour rendre la réplication entre contrôleurs de domaine efficace.

***

### <mark style="color:blue;">Built-in</mark>

Dans AD, **Built-in** est un conteneur qui contient les groupes par défaut d’un domaine AD.\
Ils sont prédéfinis lors de la création d’un domaine AD.

***

### <mark style="color:blue;">Principaux de sécurité étrangers (Foreign Security Principals)</mark>

Un **principal de sécurité étranger (FSP)** est un objet créé dans AD pour représenter un principal de sécurité appartenant à une forêt externe approuvée.

Ils sont créés lorsqu’un objet tel qu’un utilisateur, un groupe ou un ordinateur d’une forêt externe (en dehors de la forêt actuelle) est ajouté à un groupe dans le domaine courant.

Ils sont créés automatiquement après l’ajout du principal de sécurité à un groupe.

Chaque principal de sécurité étranger est un objet de type espace réservé qui contient le **SID de l’objet étranger** (un objet appartenant à une autre forêt).

Windows utilise ce SID pour résoudre le nom de l’objet via la relation d’approbation.

Les FSP sont créés dans un conteneur spécifique nommé **ForeignSecurityPrincipals** avec un nom distinctif tel que :\
`cn=ForeignSecurityPrincipals,dc=inlanefreight,dc=local`

***
