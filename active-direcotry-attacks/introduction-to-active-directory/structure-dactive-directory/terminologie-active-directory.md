# Terminologie Active Directory

## <mark style="color:red;">Terminologie Active Directory</mark>

***

### <mark style="color:blue;">Objet</mark>

> Un objet peut être défini comme TOUTE ressource présente dans un environnement Active Directory, telle que les unités organisationnelles (OU), les imprimantes, les utilisateurs, les contrôleurs de domaine, etc.

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Attributs</mark>

Chaque objet dans Active Directory possède un ensemble d'attributs associés utilisés pour définir les caractéristiques de l'objet donné.&#x20;

Un objet ordinateur contient des attributs tels que le nom d'hôte et le nom DNS. Tous les attributs dans AD ont un nom LDAP associé qui peut être utilisé lors de l'exécution de requêtes LDAP, tel que displayName pour Nom complet et givenName pour Prénom.

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Schéma</mark>

Le schéma Active Directory est essentiellement le plan directeur de tout environnement d'entreprise.&#x20;

Il définit quels types d'objets peuvent exister dans la base de données AD et leurs attributs associés.&#x20;

Il répertorie les définitions correspondant aux objets AD et contient des informations sur chaque objet.&#x20;

* Par exemple, les utilisateurs dans AD appartiennent à la classe "user", et les objets ordinateur à "computer", et ainsi de suite.&#x20;
* Chaque objet possède ses propres informations (certaines devant être définies obligatoirement et d'autres facultatives) qui sont stockées dans les Attributs.&#x20;
* Lorsqu'un objet est créé à partir d'une classe, cela s'appelle l'instanciation, et un objet créé à partir d'une classe spécifique est appelé une instance de cette classe.&#x20;
  * Par exemple, si nous prenons l'ordinateur RDS01, cet objet ordinateur est une instance de la classe "computer" dans Active Directory.

<figure><img src="../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Domaine</mark>

Un domaine est un groupe logique d'objets tels que les ordinateurs, les utilisateurs, les OU, les groupes, etc.&#x20;

Nous pouvons considérer chaque domaine comme une ville différente au sein d'un état ou d'un pays. Les domaines peuvent fonctionner entièrement indépendamment les uns des autres ou être connectés via des relations d'approbation.

***

### <mark style="color:blue;">Forêt</mark>

Une forêt est une collection de domaines Active Directory.&#x20;

C'est le conteneur le plus haut et contient tous les objets AD présentés ci-dessous, y compris mais sans s'y limiter les domaines, les utilisateurs, les groupes, les ordinateurs et les objets de stratégie de groupe.&#x20;

Une forêt peut contenir un ou plusieurs domaines et peut être considérée comme un état aux États-Unis ou un pays au sein de l'UE.&#x20;

Chaque forêt fonctionne indépendamment mais peut avoir diverses relations d'approbation avec d'autres forêts.

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Arborescence</mark>

Une arborescence est une collection de domaines Active Directory qui commence à un seul domaine racine.&#x20;

Une forêt est une collection d'arborescences AD.&#x20;

Chaque domaine dans une arborescence partage une limite avec les autres domaines.&#x20;

Une relation d'approbation parent-enfant se forme lorsqu'un domaine est ajouté sous un autre domaine dans une arborescence.&#x20;

Deux arborescences dans la même forêt ne peuvent pas partager un nom (espace de noms).&#x20;

Disons que nous avons deux arborescences dans une forêt AD : inlanefreight.local et ilfreight.local. Un domaine enfant du premier serait corp.inlanefreight.local tandis qu'un domaine enfant du second pourrait être corp.ilfreight.local. Tous les domaines dans une arborescence partagent un Catalogue global standard qui contient toutes les informations sur les objets appartenant à l'arborescence.

***

### <mark style="color:blue;">Conteneur</mark>

Les objets conteneurs contiennent d'autres objets et ont un emplacement défini dans la hiérarchie de la sous-arborescence du répertoire.

***

### <mark style="color:blue;">Feuille</mark>

Les objets feuilles ne contiennent pas d'autres objets et se trouvent à la fin de la hiérarchie de la sous-arborescence.

***

### <mark style="color:blue;">Identificateur Unique Global (GUID)</mark>

Un GUID est une valeur unique de 128 bits attribuée lors de la création d'un utilisateur ou d'un groupe de domaine.&#x20;

Cette valeur GUID est unique dans toute l'entreprise, similaire à une adresse MAC.&#x20;

Chaque objet créé par Active Directory se voit attribuer un GUID, pas seulement les objets utilisateur et groupe.

Le GUID est stocké dans l'attribut ObjectGUID.&#x20;

Lors de l'interrogation d'un objet AD (tel qu'un utilisateur, un groupe, un ordinateur, un domaine, un contrôleur de domaine, etc.), nous pouvons interroger sa valeur objectGUID à l'aide de PowerShell ou le rechercher en spécifiant son nom distinctif, son GUID, son SID ou son nom de compte SAM.&#x20;

Les GUID sont utilisés par AD pour identifier les objets en interne. La recherche dans Active Directory par valeur GUID est probablement le moyen le plus précis et le plus fiable de trouver l'objet exact que vous recherchez, surtout si le catalogue global peut contenir des correspondances similaires pour un nom d'objet.&#x20;

La spécification de la valeur ObjectGUID lors de l'énumération AD garantira que nous obtenons les résultats les plus précis concernant l'objet pour lequel nous recherchons des informations. La propriété ObjectGUID ne change jamais et est associée à l'objet tant que cet objet existe dans le domaine.

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Principaux de sécurité</mark>

Les principaux de sécurité sont tout ce que le système d'exploitation peut authentifier, y compris les utilisateurs, les comptes d'ordinateur, ou même les threads/processus qui s'exécutent dans le contexte d'un compte d'utilisateur ou d'ordinateur (c'est-à-dire une application telle que Tomcat s'exécutant dans le contexte d'un compte de service au sein du domaine).&#x20;

Dans AD, les principaux de sécurité sont des objets de domaine qui peuvent gérer l'accès à d'autres ressources dans le domaine. Nous pouvons également avoir des comptes d'utilisateurs locaux et des groupes de sécurité utilisés pour contrôler l'accès aux ressources uniquement sur cet ordinateur spécifique. Ceux-ci ne sont pas gérés par AD mais plutôt par le Gestionnaire de comptes de sécurité (SAM).

***

### <mark style="color:blue;">Identificateur de Sécurité (SID)</mark>

Un identificateur de sécurité, ou SID, est utilisé comme identifiant unique pour un principal de sécurité ou un groupe de sécurité.&#x20;

Chaque compte, groupe ou processus possède son propre SID unique, qui, dans un environnement AD, est émis par le contrôleur de domaine et stocké dans une base de données sécurisée.&#x20;

Un SID ne peut être utilisé qu'une seule fois.&#x20;

Même si le principal de sécurité est supprimé, il ne peut jamais être réutilisé dans cet environnement pour identifier un autre utilisateur ou groupe.&#x20;

Lorsqu'un utilisateur se connecte, le système crée un jeton d'accès pour lui qui contient le SID de l'utilisateur, les droits qui lui ont été accordés et les SID de tous les groupes dont l'utilisateur est membre.&#x20;

Ce jeton est utilisé pour vérifier les droits chaque fois que l'utilisateur effectue une action sur l'ordinateur.&#x20;

Il existe également des SID bien connus qui sont utilisés pour identifier des utilisateurs et des groupes génériques. Ceux-ci sont les mêmes sur tous les systèmes d'exploitation. Un exemple est le groupe Everyone.

***

### <mark style="color:blue;">Nom Distinctif (DN)</mark>

Un Nom Distinctif (DN) décrit le chemin complet vers un objet dans AD (tel que cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local).&#x20;

Dans cet exemple, l'utilisateur bjones travaille dans le département informatique de l'entreprise Inlanefreight, et son compte est créé dans une Unité Organisationnelle (OU) qui contient les comptes des employés de l'entreprise.&#x20;

Le Nom Commun (CN) bjones n'est qu'une façon dont l'objet utilisateur peut être recherché ou accessible dans le domaine.

***

### <mark style="color:blue;">Nom Distinctif Relatif (RDN)</mark>

Un Nom Distinctif Relatif (RDN) est un composant unique du Nom Distinctif qui identifie l'objet comme unique par rapport aux autres objets au niveau actuel dans la hiérarchie de nommage.&#x20;

Dans notre exemple, bjones est le Nom Distinctif Relatif de l'objet. AD ne permet pas à deux objets d'avoir le même nom sous le même conteneur parent, mais il peut y avoir deux objets avec les mêmes RDN qui sont toujours uniques dans le domaine car ils ont des DN différents.&#x20;

Par exemple, l'objet cn=bjones,dc=dev,dc=inlanefreight,dc=local serait reconnu comme différent de cn=bjones,dc=inlanefreight,dc=local.

<figure><img src="../../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">sAMAccountName</mark>

Le sAMAccountName est le nom de connexion de l'utilisateur. Ici, ce serait simplement bjones. Il doit s'agir d'une valeur unique et de 20 caractères ou moins.

***

### <mark style="color:blue;">userPrincipalName</mark>

L'attribut userPrincipalName est une autre façon d'identifier les utilisateurs dans AD. Cet attribut se compose d'un préfixe (le nom du compte utilisateur) et d'un suffixe (le nom de domaine) au format bjones@inlanefreight.local. Cet attribut n'est pas obligatoire.

***

### <mark style="color:blue;">Rôles FSMO</mark>

Aux débuts d'AD, si vous aviez plusieurs DC dans un environnement, ils se disputaient pour savoir quel DC pouvait effectuer des modifications, et parfois les modifications n'étaient pas effectuées correctement. Microsoft a alors implémenté "le dernier qui écrit gagne", ce qui pouvait introduire ses propres problèmes si la dernière modification cassait des choses.&#x20;

Ils ont ensuite introduit un modèle dans lequel un seul DC "maître" pouvait appliquer des modifications au domaine tandis que les autres se contentaient de répondre aux demandes d'authentification.&#x20;

C'était une conception défectueuse car si le DC maître tombait en panne, aucune modification ne pouvait être apportée à l'environnement tant qu'il n'était pas restauré.&#x20;

Pour résoudre ce modèle de point de défaillance unique, Microsoft a séparé les diverses responsabilités qu'un DC peut avoir en rôles d'Opération Maître Unique Flexible (FSMO).&#x20;

Ceux-ci donnent aux Contrôleurs de Domaine (DC) la capacité de continuer à authentifier les utilisateurs et à accorder des autorisations sans interruption (autorisation et authentification).

Il existe cinq rôles FSMO : Maître de schéma et Maître de nommage de domaine (un de chaque par forêt), Maître d'ID Relatif (RID) (un par domaine), Émulateur de Contrôleur de Domaine Principal (PDC) (un par domaine) et Maître d'infrastructure (un par domaine).&#x20;

Les cinq rôles sont attribués au premier DC dans le domaine racine de la forêt dans une nouvelle forêt AD. Chaque fois qu'un nouveau domaine est ajouté à une forêt, seuls les rôles de Maître RID, Émulateur PDC et Maître d'infrastructure sont attribués au nouveau domaine.&#x20;

Les rôles FSMO sont généralement définis lors de la création des contrôleurs de domaine, mais les administrateurs système peuvent transférer ces rôles si nécessaire. Ces rôles aident la réplication dans AD à fonctionner correctement et garantissent que les services critiques fonctionnent correctement. Nous examinerons chacun de ces rôles en détail plus tard dans cette section.

***

### <mark style="color:blue;">Catalogue Global</mark>

Un catalogue global (GC) est un contrôleur de domaine qui stocke des copies de TOUS les objets dans une forêt Active Directory.&#x20;

Le GC stocke une copie complète de tous les objets dans le domaine actuel et une copie partielle des objets appartenant à d'autres domaines de la forêt.&#x20;

Les contrôleurs de domaine standard détiennent une réplique complète des objets appartenant à son domaine mais pas ceux de différents domaines dans la forêt. Le GC permet aux utilisateurs et aux applications de trouver des informations sur tous les objets dans N'IMPORTE QUEL domaine de la forêt. Le GC est une fonctionnalité qui est activée sur un contrôleur de domaine et effectue les fonctions suivantes :

* **Authentification** (fournit l'autorisation pour tous les groupes auxquels un compte utilisateur appartient, qui est inclus lors de la génération d'un jeton d'accès)
* **Recherche d'objets** (rend la structure du répertoire au sein d'une forêt transparente, permettant d'effectuer une recherche dans tous les domaines d'une forêt en fournissant un seul attribut sur un objet.)

***

### <mark style="color:blue;">Contrôleur de Domaine en Lecture Seule (RODC)</mark>

Un Contrôleur de Domaine en Lecture Seule (RODC) possède une base de données Active Directory en lecture seule.&#x20;

Aucun mot de passe de compte AD n'est mis en cache sur un RODC (autre que le compte ordinateur RODC et les mots de passe KRBTGT RODC). Aucune modification n'est diffusée via la base de données AD, SYSVOL ou DNS d'un RODC. Les RODC incluent également un serveur DNS en lecture seule, permettent la séparation des rôles d'administrateur, réduisent le trafic de réplication dans l'environnement et empêchent les modifications SYSVOL d'être répliquées vers d'autres DC.

***

### <mark style="color:blue;">Réplication</mark>

La réplication se produit dans AD lorsque les objets AD sont mis à jour et transférés d'un Contrôleur de Domaine à un autre. Chaque fois qu'un DC est ajouté, des objets de connexion sont créés pour gérer la réplication entre eux. Ces connexions sont établies par le service Knowledge Consistency Checker (KCC), qui est présent sur tous les DC. La réplication garantit que les modifications sont synchronisées avec tous les autres DC d'une forêt, aidant à créer une sauvegarde au cas où un contrôleur de domaine tombe en panne.

***

### <mark style="color:blue;">Nom Principal de Service (SPN)</mark>

Un Nom Principal de Service (SPN) identifie de manière unique une instance de service. Ils sont utilisés par l'authentification Kerberos pour associer une instance d'un service à un compte de connexion, permettant à une application cliente de demander au service d'authentifier un compte sans avoir besoin de connaître le nom du compte.

***

### <mark style="color:blue;">Objet de Stratégie de Groupe (GPO)</mark>

Les Objets de Stratégie de Groupe (GPO) sont des collections virtuelles de paramètres de stratégie. Chaque GPO possède un GUID unique.&#x20;

Un GPO peut contenir des paramètres de système de fichiers local ou des paramètres Active Directory. Les paramètres GPO peuvent être appliqués aux objets utilisateur et ordinateur. Ils peuvent être appliqués à tous les utilisateurs et ordinateurs du domaine ou définis de manière plus granulaire au niveau de l'OU.

***

### <mark style="color:blue;">Liste de Contrôle d'Accès (ACL)</mark>

Une Liste de Contrôle d'Accès (ACL) est la collection ordonnée d'Entrées de Contrôle d'Accès (ACE) qui s'appliquent à un objet.

***

### <mark style="color:blue;">Entrées de Contrôle d'Accès (ACE)</mark>

Chaque Entrée de Contrôle d'Accès (ACE) dans une ACL identifie un fiduciaire (compte utilisateur, compte de groupe ou session de connexion) et répertorie les droits d'accès qui sont autorisés, refusés ou audités pour le fiduciaire donné.

***

### <mark style="color:blue;">Liste de Contrôle d'Accès Discrétionnaire (DACL)</mark>

Les DACL définissent quels principaux de sécurité se voient accorder ou refuser l'accès à un objet ; elle contient une liste d'ACE. Lorsqu'un processus tente d'accéder à un objet sécurisable, le système vérifie les ACE dans la DACL de l'objet pour déterminer s'il faut ou non accorder l'accès.&#x20;

Si un objet n'a PAS de DACL, alors le système accordera un accès complet à tout le monde, mais si la DACL n'a pas d'entrées ACE, le système refusera toutes les tentatives d'accès. Les ACE dans la DACL sont vérifiés dans l'ordre jusqu'à ce qu'une correspondance soit trouvée qui autorise les droits demandés ou jusqu'à ce que l'accès soit refusé.

***

### <mark style="color:blue;">Listes de Contrôle d'Accès Système (SACL)</mark>

Permet aux administrateurs de consigner les tentatives d'accès effectuées sur les objets sécurisés. Les ACE spécifient les types de tentatives d'accès qui amènent le système à générer un enregistrement dans le journal des événements de sécurité.

***

### <mark style="color:blue;">Nom de Domaine Complet (FQDN)</mark>

Un FQDN est le nom complet d'un ordinateur ou d'un hôte spécifique.&#x20;

Il est écrit avec le nom d'hôte et le nom de domaine au format \[nom d'hôte].\[nom de domaine].\[tld]. Ceci est utilisé pour spécifier l'emplacement d'un objet dans la hiérarchie arborescente du DNS. Le FQDN peut être utilisé pour localiser des hôtes dans un Active Directory sans connaître l'adresse IP, un peu comme lorsqu'on navigue vers un site Web tel que google.com au lieu de taper l'adresse IP associée. Un exemple serait l'hôte DC01 dans le domaine INLANEFREIGHT.LOCAL. Le FQDN ici serait DC01.INLANEFREIGHT.LOCAL.

***

### <mark style="color:blue;">Tombstone</mark>

Un tombstone est un objet conteneur dans AD qui contient les objets AD supprimés.&#x20;

Lorsqu'un objet est supprimé d'AD, l'objet reste pendant une période définie connue sous le nom de Durée de vie Tombstone, et l'attribut isDeleted est défini sur TRUE.&#x20;

Une fois qu'un objet dépasse la Durée de vie Tombstone, il sera entièrement supprimé. Microsoft recommande une durée de vie tombstone de 180 jours pour augmenter l'utilité des sauvegardes, mais cette valeur peut différer selon les environnements.&#x20;

Selon la version du système d'exploitation du DC, cette valeur sera par défaut de 60 ou 180 jours. Si un objet est supprimé dans un domaine qui n'a pas de Corbeille AD, il deviendra un objet tombstone. Lorsque cela se produit, l'objet est dépouillé de la plupart de ses attributs et placé dans le conteneur Objets supprimés pour la durée de la tombstoneLifetime. Il peut être récupéré, mais tous les attributs qui ont été perdus ne peuvent plus être récupérés.

***

### <mark style="color:blue;">Corbeille AD</mark>

La Corbeille AD a été introduite pour la première fois dans Windows Server 2008 R2 pour faciliter la récupération des objets AD supprimés. Cela a facilité la tâche des administrateurs système pour restaurer les objets, évitant la nécessité de restaurer à partir de sauvegardes, de redémarrer les Services de Domaine Active Directory (AD DS) ou de redémarrer un Contrôleur de Domaine.&#x20;

Lorsque la Corbeille AD est activée, tous les objets supprimés sont préservés pendant une période de temps, facilitant la restauration si nécessaire. Les administrateurs système peuvent définir la durée pendant laquelle un objet reste dans un état supprimé et récupérable.&#x20;

Si cela n'est pas spécifié, l'objet sera restaurable pour une valeur par défaut de 60 jours. Le plus grand avantage de l'utilisation de la Corbeille AD est que la plupart des attributs d'un objet supprimé sont préservés, ce qui facilite grandement la restauration complète d'un objet supprimé à son état précédent.

***

### <mark style="color:blue;">SYSVOL</mark>

Le dossier SYSVOL, ou partage, stocke des copies de fichiers publics dans le domaine tels que les stratégies système, les paramètres de Stratégie de Groupe, les scripts de connexion/déconnexion, et contient souvent d'autres types de scripts qui sont exécutés pour effectuer diverses tâches dans l'environnement AD. Le contenu du dossier SYSVOL est répliqué sur tous les DC de l'environnement à l'aide des Services de Réplication de Fichiers (FRS).

***

### <mark style="color:blue;">AdminSDHolder</mark>

L'objet AdminSDHolder est utilisé pour gérer les ACL pour les membres de groupes intégrés dans AD marqués comme privilégiés.&#x20;

Il agit comme un conteneur qui contient le Descripteur de Sécurité appliqué aux membres des groupes protégés.&#x20;

Le processus SDProp (SD Propagator) s'exécute selon un calendrier sur le Contrôleur de Domaine Émulateur PDC. Lorsque ce processus s'exécute, il vérifie les membres des groupes protégés pour s'assurer que l'ACL correcte leur est appliquée. Il s'exécute toutes les heures par défaut. Par exemple, supposons qu'un attaquant soit capable de créer une entrée ACL malveillante pour accorder à un utilisateur certains droits sur un membre du groupe Admins du domaine. Dans ce cas, à moins qu'ils ne modifient d'autres paramètres dans AD, ces droits seront supprimés (et ils perdront toute persistance qu'ils espéraient obtenir) lorsque le processus SDProp s'exécutera à l'intervalle défini.

***

### <mark style="color:blue;">**dsHeuristics**</mark>

L'attribut dsHeuristics est une valeur de chaîne définie sur l'objet Service d'annuaire utilisé pour définir plusieurs paramètres de configuration à l'échelle de la forêt.&#x20;

L'un de ces paramètres consiste à exclure les groupes intégrés de la liste des Groupes Protégés.&#x20;

Les groupes de cette liste sont protégés contre les modifications via l'objet AdminSDHolder. Si un groupe est exclu via l'attribut dsHeuristics, alors toutes les modifications qui l'affectent ne seront pas annulées lorsque le processus SDProp s'exécute.

***

### <mark style="color:blue;">adminCount</mark>

L'attribut adminCount détermine si le processus SDProp protège ou non un utilisateur. Si la valeur est définie sur 0 ou non spécifiée, l'utilisateur n'est pas protégé. Si la valeur de l'attribut est définie sur 1, l'utilisateur est protégé. Les attaquants rechercheront souvent des comptes avec l'attribut adminCount défini sur 1 à cibler dans un environnement interne. Ce sont souvent des comptes privilégiés et peuvent conduire à un accès supplémentaire ou à un compromis complet du domaine.

***

### <mark style="color:blue;">Utilisateurs et Ordinateurs Active Directory (ADUC)</mark>

ADUC est une console GUI couramment utilisée pour gérer les utilisateurs, les groupes, les ordinateurs et les contacts dans AD. Les modifications effectuées dans ADUC peuvent également être effectuées via PowerShell.

***

### <mark style="color:blue;">ADSI Edit</mark>

ADSI Edit est un outil GUI utilisé pour gérer les objets dans AD. Il fournit un accès à beaucoup plus que ce qui est disponible dans ADUC et peut être utilisé pour définir ou supprimer n'importe quel attribut disponible sur un objet, ajouter, supprimer et déplacer des objets également. C'est un outil puissant qui permet à un utilisateur d'accéder à AD à un niveau beaucoup plus profond. Une grande attention doit être portée lors de l'utilisation de cet outil, car les modifications ici pourraient causer des problèmes majeurs dans AD.

***

### <mark style="color:blue;">sIDHistory</mark>

Cet attribut contient tous les SID qui ont été précédemment attribués à un objet. Il est généralement utilisé dans les migrations afin qu'un utilisateur puisse maintenir le même niveau d'accès lorsqu'il est migré d'un domaine à un autre. Cet attribut peut potentiellement être abusé s'il est défini de manière non sécurisée, permettant à un attaquant d'obtenir l'accès élevé précédent qu'un compte avait avant une migration si le Filtrage SID (ou la suppression des SID d'un autre domaine du jeton d'accès d'un utilisateur qui pourrait être utilisé pour un accès élevé) n'est pas activé.

***

### <mark style="color:blue;">NTDS.DIT</mark>

Le fichier NTDS.DIT peut être considéré comme le cœur d'Active Directory.&#x20;

Il est stocké sur un Contrôleur de Domaine à C:\Windows\NTDS\ et est une base de données qui stocke les données AD telles que des informations sur les objets utilisateur et groupe, l'appartenance aux groupes et, plus important pour les attaquants et les testeurs de pénétration, les hachages de mots de passe pour tous les utilisateurs du domaine.&#x20;

Une fois le compromis complet du domaine atteint, un attaquant peut récupérer ce fichier, extraire les hachages et soit les utiliser pour effectuer une attaque pass-the-hash, soit les craquer hors ligne à l'aide d'un outil tel que Hashcat pour accéder à des ressources supplémentaires dans le domaine.&#x20;

Si le paramètre Stocker le mot de passe avec chiffrement réversible est activé, alors le NTDS.DIT stockera également les mots de passe en clair pour tous les utilisateurs créés ou qui ont changé leur mot de passe après la définition de cette stratégie. Bien que rare, certaines organisations peuvent activer ce paramètre si elles utilisent des applications ou des protocoles qui doivent utiliser le mot de passe existant d'un utilisateur (et non Kerberos) pour l'authentification.

***

### <mark style="color:blue;">MSBROWSE</mark>

MSBROWSE est un protocole de mise en réseau Microsoft qui était utilisé dans les premières versions des réseaux locaux (LAN) Windows pour fournir des services de navigation. Il était utilisé pour maintenir une liste de ressources, telles que des imprimantes et des fichiers partagés, qui étaient disponibles sur le réseau, et pour permettre aux utilisateurs de naviguer et d'accéder facilement à ces ressources.

Dans les anciennes versions de Windows, nous pouvions utiliser nbtstat -A adresse-ip pour rechercher le Navigateur Maître. Si nous voyons MSBROWSE, cela signifie que c'est le Navigateur Maître. De plus, nous pouvions utiliser l'utilitaire nltest pour interroger un Navigateur Maître Windows pour les noms des Contrôleurs de Domaine.

Aujourd'hui, MSBROWSE est largement obsolète et n'est plus largement utilisé. Les LAN Windows modernes utilisent le protocole Server Message Block (SMB) pour le partage de fichiers et d'imprimantes, et le protocole Common Internet File System (CIFS) pour les services de navigation.

***
