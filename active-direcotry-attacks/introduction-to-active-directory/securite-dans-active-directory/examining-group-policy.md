# Examining Group Policy

## <mark style="color:red;">Examen de la Stratégie de Groupe</mark>

La stratégie de groupe est une fonctionnalité Windows qui fournit aux administrateurs un large éventail de paramètres avancés qui peuvent s'appliquer à la fois aux comptes utilisateurs et ordinateurs dans un environnement Windows. Chaque hôte Windows dispose d'un éditeur de stratégie de groupe local pour gérer les paramètres locaux.

Pour nos besoins, nous nous concentrerons sur la stratégie de groupe dans un contexte de domaine pour gérer les utilisateurs et les ordinateurs dans Active Directory. La stratégie de groupe est un outil puissant pour gérer et configurer les paramètres utilisateur, les systèmes d'exploitation et les applications. La stratégie de groupe est également un outil puissant pour gérer la sécurité dans un environnement de domaine.

Du point de vue de la sécurité, exploiter la stratégie de groupe est l'un des meilleurs moyens d'affecter largement la posture de sécurité de votre entreprise. Active Directory n'est en aucun cas sécurisé "prêt à l'emploi", et la stratégie de groupe, lorsqu'elle est utilisée correctement, est une partie cruciale d'une stratégie de défense en profondeur.

Bien que la stratégie de groupe soit un excellent outil pour gérer la sécurité d'un domaine, elle peut également être exploitée par des attaquants. Obtenir des droits sur un objet de stratégie de groupe pourrait conduire à un mouvement latéral, une escalade de privilèges, et même une compromission complète du domaine si l'attaquant peut les exploiter de manière à prendre le contrôle d'un utilisateur ou d'un ordinateur de grande valeur. Ils peuvent également être utilisés comme moyen pour un attaquant de maintenir la persistance au sein d'un réseau.

Comprendre comment fonctionne la stratégie de groupe nous donnera un avantage contre les attaquants et peut nous aider grandement lors des tests d'intrusion, trouvant parfois des mauvaises configurations nuancées que d'autres testeurs d'intrusion pourraient manquer.

***

### <mark style="color:blue;">Objets de Stratégie de Groupe (GPO)</mark>

Un objet de stratégie de groupe (GPO) est une collection virtuelle de paramètres de politique qui peuvent être appliqués à un ou plusieurs utilisateurs ou ordinateurs. Les GPO incluent des politiques telles que le délai de verrouillage de l'écran, la désactivation des ports USB, l'application d'une politique de mot de passe de domaine personnalisée, l'installation de logiciels, la gestion des applications, la personnalisation des paramètres d'accès distant, et bien plus encore.

Chaque GPO a un nom unique et se voit attribuer un identifiant unique (un GUID). Ils peuvent être liés à une OU, un domaine ou un site spécifique. Un seul GPO peut être lié à plusieurs conteneurs, et tout conteneur peut avoir plusieurs GPO appliqués. Ils peuvent être appliqués à des utilisateurs, hôtes ou groupes individuels en étant appliqués directement à une OU.

Chaque GPO contient un ou plusieurs paramètres de stratégie de groupe qui peuvent s'appliquer au niveau de la machine locale ou dans le contexte Active Directory.

***

### <mark style="color:blue;">Exemples de GPO</mark>

Voici quelques exemples de ce que nous pouvons faire avec les GPO :

* Établir différentes politiques de mot de passe pour les comptes de service, les comptes administrateurs et les comptes utilisateurs standard en utilisant des GPO séparés
* Empêcher l'utilisation de périphériques de médias amovibles (tels que les périphériques USB)
* Imposer un économiseur d'écran avec un mot de passe
* Restreindre l'accès aux applications dont un utilisateur standard peut ne pas avoir besoin, telles que cmd.exe et PowerShell
* Imposer des politiques d'audit et de journalisation
* Empêcher les utilisateurs d'exécuter certains types de programmes et de scripts
* Déployer des logiciels dans un domaine
* Empêcher les utilisateurs d'installer des logiciels non approuvés
* Afficher une bannière de connexion chaque fois qu'un utilisateur se connecte à un système
* Interdire l'utilisation du hachage LM dans le domaine
* Exécuter des scripts lorsque les ordinateurs démarrent/s'arrêtent ou lorsqu'un utilisateur se connecte/se déconnecte de sa machine

***

#### <mark style="color:green;">Exemple de Politique de Mot de Passe</mark>

Prenons comme exemple une implémentation Active Directory par défaut de Windows Server 2008, la complexité du mot de passe est imposée par défaut. Les exigences de complexité du mot de passe sont les suivantes :

* Les mots de passe doivent comporter au moins 7 caractères
* Les mots de passe doivent contenir des caractères d'au moins trois des quatre catégories suivantes :
  * Caractères majuscules (A-Z)
  * Caractères minuscules (a-z)
  * Chiffres (0-9)
  * Caractères spéciaux (par exemple !@#$%^&\*()\_+|\~-=\`{}:";'<>?,. /)

Ce ne sont que quelques exemples de ce qui peut être fait avec la stratégie de groupe. Il existe des centaines de paramètres qui peuvent être appliqués dans un GPO, ce qui peut devenir extrêmement granulaire. Par exemple, ci-dessous se trouvent quelques options que nous pouvons définir pour les sessions Remote Desktop.

Les paramètres GPO sont traités en utilisant la structure hiérarchique d'AD et sont appliqués en utilisant la règle d'ordre de préséance comme on peut le voir dans le tableau ci-dessous.

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

***

### <mark style="color:blue;">Ordre de Préséance</mark>

#### Tableau de l'Ordre de Préséance

**Stratégie de Groupe Locale (Local Group Policy)** Les politiques sont définies directement sur l'hôte localement en dehors du domaine. Tout paramètre ici sera écrasé si un paramètre similaire est défini à un niveau supérieur.

**Politique de Site (Site Policy)** Toutes les politiques spécifiques au site d'entreprise où réside l'hôte. Rappelez-vous que les environnements d'entreprise peuvent s'étendre sur de grands campus et même à travers les pays. Il est donc logique qu'un site puisse avoir ses propres politiques à suivre qui pourraient le différencier du reste de l'organisation.

Les politiques de contrôle d'accès sont un excellent exemple de cela. Supposons qu'un bâtiment ou un site spécifique effectue des recherches secrètes ou restreintes et nécessite un niveau d'autorisation plus élevé pour l'accès aux ressources. Vous pourriez spécifier ces paramètres au niveau du site et vous assurer qu'ils sont liés pour ne pas être écrasés par la politique de domaine. C'est également un excellent moyen d'effectuer des actions comme le mappage d'imprimantes et de partages pour les utilisateurs dans des sites spécifiques.

**Politique à l'Échelle du Domaine (Domain-wide Policy)** Tous les paramètres que vous souhaitez appliquer dans l'ensemble du domaine. Par exemple, définir le niveau de complexité de la politique de mot de passe, configurer un fond d'écran de bureau pour tous les utilisateurs, et définir une bannière d'avis d'utilisation et de consentement à surveiller à l'écran de connexion.

**Unité Organisationnelle (OU)** Ces paramètres affecteraient les utilisateurs et les ordinateurs qui appartiennent à des OU spécifiques. Vous voudriez placer ici tous les paramètres uniques qui sont spécifiques au rôle. Par exemple, le mappage d'un lecteur de partage particulier qui ne peut être accessible que par les RH, l'accès à des ressources spécifiques comme les imprimantes, ou la capacité pour les administrateurs IT d'utiliser PowerShell et l'invite de commande.

**Toutes Politiques d'OU Imbriquées dans d'Autres OU** Les paramètres à ce niveau refléteraient des permissions spéciales pour les objets au sein d'OU imbriquées. Par exemple, fournir aux analystes de sécurité un ensemble spécifique de paramètres de politique Applocker qui diffèrent des paramètres Applocker IT standard.

***

### <mark style="color:blue;">Gestion de la Stratégie de Groupe</mark>

Nous pouvons gérer la stratégie de groupe à partir de la console de gestion de stratégie de groupe (trouvée sous Outils d'administration dans le menu Démarrer sur un contrôleur de domaine), des applications personnalisées, ou en utilisant le module PowerShell GroupPolicy via la ligne de commande.

La **Default Domain Policy** est le GPO par défaut qui est automatiquement créé et lié au domaine. Il a la priorité la plus élevée de tous les GPO et est appliqué par défaut à tous les utilisateurs et ordinateurs. Généralement, c'est une meilleure pratique d'utiliser ce GPO par défaut pour gérer les paramètres par défaut qui s'appliqueront à l'échelle du domaine.

La **Default Domain Controllers Policy** est également créée automatiquement avec un domaine et définit les paramètres de sécurité et d'audit de base pour tous les contrôleurs de domaine dans un domaine donné. Elle peut être personnalisée selon les besoins, comme n'importe quel GPO.

***

### Ordre de Préséance des GPO

Les GPO sont traités de haut en bas lorsqu'on les visualise du point de vue organisationnel du domaine. Un GPO lié à une OU au niveau le plus élevé dans un réseau Active Directory (au niveau du domaine, par exemple) serait traité en premier, suivi de ceux liés à une OU enfant, etc.

Cela signifie qu'un GPO lié directement à une OU contenant des objets utilisateur ou ordinateur est traité en dernier. En d'autres termes, un GPO attaché à une OU spécifique aurait la préséance sur un GPO attaché au niveau du domaine car il sera traité en dernier et pourrait courir le risque d'écraser les paramètres dans un GPO plus haut dans la hiérarchie du domaine.

Une chose de plus à suivre avec la préséance est qu'un paramètre configuré dans la politique Ordinateur aura toujours une priorité plus élevée que le même paramètre appliqué à un utilisateur.

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:blue;">Exemple de Préséance</mark>

Regardons un autre exemple en utilisant la console de gestion de stratégie de groupe sur un contrôleur de domaine. Dans cette image, nous voyons plusieurs GPO. Le GPO **Disabled Forced Restarts** aura la préséance sur le GPO **Logon Banner** car il serait traité en dernier. Tous les paramètres configurés dans le GPO Disabled Forced Restarts pourraient potentiellement écraser les paramètres dans tous les GPO plus haut dans la hiérarchie (y compris ceux liés à l'OU Corp).

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Cette image montre également un exemple de plusieurs GPO liés à l'OU Corp. Lorsque plus d'un GPO est lié à une OU, ils sont traités en fonction de l'**ordre de liaison (Link Order)**. Le GPO avec l'ordre de liaison le plus bas est traité en dernier, ou le GPO avec l'ordre de liaison 1 a la priorité la plus élevée, puis 2, et 3, et ainsi de suite.

Donc dans notre exemple ci-dessus, le GPO **Disallow LM Hash** aura la préséance sur les GPO **Block Removable Media** et **Disable Guest Account**, ce qui signifie qu'il sera traité en premier.

### <mark style="color:green;">Option "Enforced" (Appliqué)</mark>

Il est possible de spécifier l'option **Enforced** pour appliquer les paramètres dans un GPO spécifique. Si cette option est définie, les paramètres de politique dans les GPO liés à des OU inférieures NE PEUVENT PAS écraser les paramètres.

Si un GPO est défini au niveau du domaine avec l'option Enforced sélectionnée, les paramètres contenus dans ce GPO seront appliqués à toutes les OU du domaine et ne peuvent pas être écrasés par les politiques d'OU de niveau inférieur.

Dans le passé, ce paramètre s'appelait **No Override** et était défini sur le conteneur en question sous Utilisateurs et ordinateurs Active Directory.

Quel que soit le GPO défini comme appliqué, si le GPO **Default Domain Policy** est appliqué, il aura la préséance sur tous les GPO à tous les niveaux.

***

### Option "Block Inheritance" (Bloquer l'Héritage)

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

Il est également possible de définir l'option **Block inheritance** sur une OU. Si cela est spécifié pour une OU particulière, alors les politiques plus haut (telles qu'au niveau du domaine) NE seront PAS appliquées à cette OU.

Si les deux options sont définies, l'option No Override a la préséance sur l'option Block inheritance.

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Fréquence de Rafraîchissement de la Stratégie de Groupe</mark>

Lorsqu'un nouveau GPO est créé, les paramètres ne sont pas automatiquement appliqués immédiatement. Windows effectue des mises à jour périodiques de la stratégie de groupe, qui par défaut sont effectuées toutes les **90 minutes** avec un décalage aléatoire de +/- 30 minutes pour les utilisateurs et les ordinateurs.

La période n'est que de **5 minutes** pour que les contrôleurs de domaine se mettent à jour par défaut. Lorsqu'un nouveau GPO est créé et lié, il pourrait prendre jusqu'à 2 heures (120 minutes) avant que les paramètres ne prennent effet. Ce décalage aléatoire de +/- 30 minutes est défini pour éviter de submerger les contrôleurs de domaine en ayant tous les clients demander la stratégie de groupe au contrôleur de domaine simultanément.

Il est possible de modifier l'intervalle de rafraîchissement par défaut dans la stratégie de groupe elle-même. De plus, nous pouvons émettre la commande `gpupdate /force` pour lancer le processus de mise à jour. Cette commande comparera les GPO actuellement appliqués sur la machine par rapport au contrôleur de domaine et les modifiera ou les ignorera selon qu'ils ont changé depuis la dernière mise à jour automatique.

Nous pouvons modifier l'intervalle de rafraîchissement via la stratégie de groupe en cliquant sur **Configuration ordinateur --> Stratégies --> Modèles d'administration --> Système --> Stratégie de groupe** et en sélectionnant **Définir l'intervalle de rafraîchissement de la stratégie de groupe pour les ordinateurs**.

Bien qu'il puisse être modifié, il ne devrait pas être configuré pour se produire trop souvent, ou il pourrait causer une congestion du réseau conduisant à des problèmes de réplication.

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Considérations de Sécurité des GPO</mark>

Comme mentionné précédemment, les GPO peuvent être utilisés pour effectuer des attaques. Ces attaques peuvent inclure l'ajout de droits supplémentaires à un compte utilisateur que nous contrôlons, l'ajout d'un administrateur local à un hôte, ou la création d'une tâche planifiée immédiate pour exécuter une commande malveillante telle que la modification de l'appartenance à un groupe, l'ajout d'un nouveau compte administrateur, l'établissement d'une connexion shell inversée, ou même l'installation de logiciels malveillants ciblés dans tout un domaine.

Ces attaques se produisent généralement lorsqu'un utilisateur possède les droits requis pour modifier un GPO qui s'applique à une OU qui contient soit un compte utilisateur que nous contrôlons, soit un ordinateur.

Ci-dessous se trouve un exemple de chemin d'attaque GPO identifié à l'aide de l'outil BloodHound. Cet exemple montre que le groupe **Domain Users** peut modifier le GPO **Disconnect Idle RDP** en raison de l'appartenance à un groupe imbriqué. Dans ce cas, nous examinerions ensuite à quelles OU ce GPO s'applique et si nous pouvons exploiter ces droits pour prendre le contrôle d'un utilisateur de grande valeur (administrateur ou Domain Admin) ou d'un ordinateur (serveur, DC ou hôte critique) et nous déplacer latéralement pour escalader les privilèges au sein du domaine.

***
