# Sécurité dans Active Directory

## <mark style="color:red;">Sécurité dans Active Directory</mark>

Au fur et à mesure que nous avons progressé dans ce module, nous avons examiné les nombreuses fonctionnalités intégrées dans Active Directory. Toutes sont construites autour de la prémisse de la gestion centralisée et de la capacité de partager des informations rapidement, à volonté, à une large base d'utilisateurs.

Active Directory peut être considéré comme non sécurisé par conception à cause de cela. Une installation Active Directory par défaut sera dépourvue de nombreuses mesures de renforcement, paramètres et outils qui peuvent être utilisés pour sécuriser une implémentation AD.

***

### <mark style="color:blue;">La Triade CIA</mark>

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Lorsque nous pensons à la cybersécurité, l'une des premières choses qui viennent à l'esprit est l'équilibre entre la **Confidentialité**, l'**Intégrité** et la **Disponibilité**, également connu sous le nom de triade CIA. Trouver cet équilibre est difficile, et AD penche fortement vers la disponibilité et la confidentialité dans son cœur.

Nous pouvons aider à équilibrer la balance en utilisant les fonctionnalités intégrées de Microsoft qui peuvent être activées/ajustées pour renforcer AD contre les attaques courantes.

***

### <mark style="color:blue;">Mesures Générales de Renforcement d'Active Directory</mark>

#### <mark style="color:green;">LAPS (Microsoft Local Administrator Password Solution)</mark>

La solution Microsoft Local Administrator Password Solution (LAPS) est utilisée pour randomiser et faire tourner les mots de passe des administrateurs locaux sur les hôtes Windows et prévenir les mouvements latéraux.

Les comptes peuvent être configurés pour que leur mot de passe soit changé à intervalle fixe (par exemple, 12 heures, 24 heures, etc.). Cet outil gratuit peut être bénéfique pour réduire l'impact d'un hôte individuel compromis dans un environnement AD.

Les organisations ne devraient pas se fier uniquement à des outils comme celui-ci. Néanmoins, lorsqu'il est combiné avec d'autres mesures de renforcement et meilleures pratiques de sécurité, il peut être un outil très efficace pour la gestion des mots de passe des comptes administrateurs locaux.

#### <mark style="color:green;">Paramètres de Politique d'Audit (Journalisation et Surveillance)</mark>

Chaque organisation doit avoir une journalisation et une surveillance configurées pour détecter et réagir aux changements ou activités inattendus qui peuvent indiquer une attaque.

Une journalisation et une surveillance efficaces peuvent être utilisées pour détecter un attaquant ou un employé non autorisé ajoutant un utilisateur ou un ordinateur, modifiant un objet dans AD, changeant un mot de passe de compte, accédant à un système de manière non autorisée ou non standard, effectuant une attaque telle que le password spraying, ou des attaques plus avancées telles que les attaques Kerberos modernes.

#### <mark style="color:green;">Paramètres de Sécurité de la Stratégie de Groupe</mark>

Comme mentionné précédemment dans le module, les objets de stratégie de groupe (GPO) sont des collections virtuelles de paramètres de politique qui peuvent être appliqués à des utilisateurs, groupes et ordinateurs spécifiques au niveau de l'OU.

Ceux-ci peuvent être utilisés pour appliquer une grande variété de politiques de sécurité pour aider à renforcer Active Directory. Voici une liste non exhaustive des types de politiques de sécurité qui peuvent être appliquées :

* **Politiques de Compte** Gèrent comment les comptes utilisateurs interagissent avec le domaine. Celles-ci incluent la politique de mot de passe, la politique de verrouillage de compte et les paramètres liés à Kerberos tels que la durée de vie des tickets Kerberos.
* **Politiques Locales** Celles-ci s'appliquent à un ordinateur spécifique et incluent la politique d'audit des événements de sécurité, les attributions de droits utilisateur (privilèges utilisateur sur un hôte), et des paramètres de sécurité spécifiques tels que la capacité d'installer des pilotes, si les comptes administrateur et invité sont activés, le renommage des comptes invité et administrateur, empêcher les utilisateurs d'installer des imprimantes ou d'utiliser des médias amovibles, et une variété de contrôles d'accès réseau et de sécurité réseau.
* **Politiques de Restriction de Logiciels** Paramètres pour contrôler quels logiciels peuvent être exécutés sur un hôte.
* **Politiques de Contrôle d'Application** Paramètres pour contrôler quelles applications peuvent être exécutées par certains utilisateurs/groupes. Cela peut inclure le blocage de certains utilisateurs pour qu'ils n'exécutent pas tous les exécutables, les fichiers Windows Installer, les scripts, etc.
* Les administrateurs utilisent AppLocker pour restreindre l'accès à certains types d'applications et de fichiers. Il n'est pas rare de voir des organisations bloquer l'accès à CMD et PowerShell (entre autres exécutables) pour les utilisateurs qui n'en ont pas besoin pour leur travail quotidien. Ces politiques sont imparfaites et peuvent souvent être contournées mais sont nécessaires pour une stratégie de défense en profondeur.
* **Configuration de la Politique d'Audit Avancée** Une variété de paramètres qui peuvent être ajustés pour auditer des activités telles que l'accès ou la modification de fichiers, la connexion/déconnexion de compte, les changements de politique, l'utilisation de privilèges, et plus encore.

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

***

#### <mark style="color:green;">Gestion des Mises à Jour (SCCM/WSUS)</mark>

Une gestion appropriée des correctifs est critique pour toute organisation, en particulier celles exécutant des systèmes Windows/Active Directory.

Le Windows Server Update Service (WSUS) peut être installé en tant que rôle sur un serveur Windows et peut être utilisé pour minimiser la tâche manuelle de correction des systèmes Windows.

System Center Configuration Manager (SCCM) est une solution payante qui repose sur le rôle Windows Server WSUS étant installé et offre plus de fonctionnalités que WSUS seul.

Une solution de gestion des correctifs peut aider à assurer un déploiement en temps opportun des correctifs et maximiser la couverture, en s'assurant qu'aucun hôte ne manque des correctifs de sécurité critiques. Si une organisation s'appuie sur une méthode manuelle pour appliquer des correctifs, cela pourrait prendre très longtemps selon la taille de l'environnement et pourrait également entraîner que des systèmes soient manqués et laissés vulnérables.

***

#### <mark style="color:green;">Comptes de Service Gérés par Groupe (gMSA)</mark>

Un gMSA est un compte géré par le domaine qui offre un niveau de sécurité plus élevé que d'autres types de comptes de service pour une utilisation avec des applications, services, processus et tâches non interactifs qui sont exécutés automatiquement mais nécessitent des informations d'identification pour s'exécuter.

Ils fournissent une gestion automatique des mots de passe avec un mot de passe de 120 caractères généré par le contrôleur de domaine. Le mot de passe est changé à intervalle régulier et n'a pas besoin d'être connu par aucun utilisateur. Il permet d'utiliser des informations d'identification sur plusieurs hôtes.

***

#### <mark style="color:green;">Groupes de Sécurité</mark>

Les groupes de sécurité offrent un moyen facile d'assigner l'accès aux ressources réseau. Ils peuvent être utilisés pour assigner des droits spécifiques au groupe (au lieu de directement à l'utilisateur) pour déterminer ce que les membres du groupe peuvent faire dans l'environnement AD.

Active Directory crée automatiquement certains groupes de sécurité par défaut lors de l'installation. Quelques exemples sont Account Operators, Administrators, Backup Operators, Domain Admins et Domain Users.

Ces groupes peuvent également être utilisés pour assigner la permission d'accéder aux ressources (par exemple, un partage de fichiers, un dossier, une imprimante ou un document). Les groupes de sécurité aident à garantir que vous pouvez assigner des permissions granulaires aux utilisateurs en masse au lieu de gérer individuellement chaque utilisateur.

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

***

#### <mark style="color:green;">Séparation des Comptes</mark>

Les administrateurs doivent avoir deux comptes séparés. Un pour leur travail quotidien et un second pour toutes les tâches administratives qu'ils doivent effectuer.

Par exemple, un utilisateur pourrait se connecter à sa machine en utilisant son compte sjones pour envoyer/recevoir des emails, créer des documents, etc. Ils devraient avoir un compte séparé, tel que sjones\_adm, pour accéder à un hôte administratif sécurisé utilisé pour effectuer des tâches administratives.

Cela peut aider à garantir que si l'hôte d'un utilisateur est compromis (par une attaque de phishing, par exemple), l'attaquant serait limité à cet hôte et n'obtiendrait pas d'informations d'identification pour un utilisateur hautement privilégié avec un accès considérable dans le domaine.

Il est également essentiel que l'individu utilise des mots de passe différents pour chaque compte afin d'atténuer le risque d'attaques de réutilisation de mot de passe si son compte non-admin est compromis.

***

#### <mark style="color:green;">Politiques de Complexité de Mot de Passe + Phrases de Passe + 2FA</mark>

Idéalement, une organisation devrait utiliser des phrases de passe ou de grands mots de passe générés aléatoirement en utilisant un gestionnaire de mots de passe d'entreprise.

Les mots de passe standard de 7-8 caractères peuvent être craqués hors ligne en utilisant un outil tel que Hashcat très rapidement avec une plateforme de craquage de mots de passe GPU. Les mots de passe plus courts et moins complexes peuvent également être devinés par une attaque de password spraying, donnant à un attaquant une prise initiale dans le domaine.

Les règles de complexité de mot de passe seules dans AD ne suffisent pas à garantir des mots de passe forts. Par exemple, le mot de passe Welcome1 répondrait aux règles de complexité standard (3 sur 4 parmi majuscule, minuscule, chiffre et caractère spécial) mais serait l'un des premiers mots de passe que j'essaierais dans une attaque de password spraying.

Une organisation devrait également envisager de mettre en œuvre un filtre de mot de passe pour interdire les mots de passe contenant les mois ou saisons de l'année, le nom de l'entreprise et des mots courants tels que password et welcome.

La longueur minimale du mot de passe pour les utilisateurs standard devrait être d'au moins 12 caractères et idéalement plus longue pour les administrateurs/comptes de service.

Une autre mesure de sécurité importante est la mise en œuvre de l'authentification multifacteur (MFA) pour l'accès Remote Desktop à n'importe quel hôte. Cela peut aider à limiter les tentatives de mouvement latéral qui peuvent s'appuyer sur l'accès GUI à un hôte.

***

#### <mark style="color:green;">Limitation de l'Utilisation du Compte Domain Admin</mark>

Les comptes Domain Admin tout-puissants ne devraient être utilisés que pour se connecter aux contrôleurs de domaine, pas aux stations de travail personnelles, hôtes de saut, serveurs web, etc.

Cela peut réduire considérablement l'impact d'une attaque et réduire les chemins d'attaque potentiels si un hôte est compromis. Cela garantirait que les mots de passe des comptes Domain Admin ne sont pas laissés en mémoire sur les hôtes à travers l'environnement.

***

#### <mark style="color:green;">Audit Périodique et Suppression des Utilisateurs et Objets Obsolètes</mark>

Il est important pour une organisation d'auditer périodiquement Active Directory et de supprimer ou désactiver tous les comptes inutilisés.

Par exemple, il peut y avoir un compte de service privilégié qui a été créé il y a huit ans avec un mot de passe très faible qui n'a jamais été changé, et le compte n'est plus utilisé. Même si la politique de mot de passe avait depuis été changée pour être plus résistante aux attaques telles que le password spraying, un compte comme celui-ci peut être une prise initiale rapide et facile ou une méthode de mouvement latéral ou d'escalade de privilèges au sein du domaine.

***

#### <mark style="color:green;">Audit des Permissions et de l'Accès</mark>

Les organisations devraient également effectuer périodiquement des audits de contrôle d'accès pour s'assurer que les utilisateurs n'ont que le niveau d'accès requis pour leur travail quotidien.

Il est important d'auditer les droits d'administrateur local, le nombre de Domain Admins (avons-nous vraiment besoin de 30 d'entre eux ?), et les Enterprise Admins pour limiter la surface d'attaque, l'accès aux partages de fichiers, les droits utilisateur (c'est-à-dire l'appartenance à certains groupes de sécurité privilégiés), et plus encore.

#### <mark style="color:green;">Politiques d'Audit et Journalisation</mark>

La visibilité dans le domaine est indispensable. Une organisation peut y parvenir par une journalisation robuste, puis en utilisant des règles pour détecter une activité anormale (telle que de nombreuses tentatives de connexion échouées qui pourraient indiquer une attaque de password spraying) ou des indicateurs qu'une attaque Kerberoasting est tentée.

Ceux-ci peuvent également être utilisés pour détecter l'énumération Active Directory. Il vaut la peine de nous familiariser avec les recommandations de politique d'audit de Microsoft pour aider à détecter la compromission.

***

#### <mark style="color:green;">Utilisation de Groupes Restreints</mark>

Les groupes restreints permettent aux administrateurs de configurer l'appartenance à un groupe via la stratégie de groupe. Ils peuvent être utilisés pour un certain nombre de raisons, telles que contrôler l'appartenance au groupe des administrateurs locaux sur tous les hôtes du domaine en le limitant uniquement au compte Administrateur local et aux Domain Admins, et contrôler l'appartenance aux groupes hautement privilégiés Enterprise Admins et Schema Admins et autres groupes administratifs clés.

***

#### <mark style="color:green;">Limitation des Rôles de Serveur</mark>

Il est important de ne pas installer de rôles supplémentaires sur des hôtes sensibles, comme installer le rôle Internet Information Server (IIS) sur un contrôleur de domaine.

Cela augmenterait la surface d'attaque du contrôleur de domaine, et ce type de rôle devrait être installé sur un serveur web autonome séparé. Quelques autres exemples seraient de ne pas héberger d'applications web sur un serveur de messagerie Exchange et de séparer les serveurs web et les serveurs de base de données sur différents hôtes.

Ce type de séparation de rôles peut aider à réduire l'impact d'une attaque réussie.

#### <mark style="color:green;">Limitation des Droits d'Administrateur Local et RDP</mark>

Les organisations devraient contrôler étroitement quels utilisateurs ont des droits d'administrateur local sur quels ordinateurs. Comme indiqué ci-dessus, cela peut être réalisé en utilisant des groupes restreints.

J'ai vu trop d'organisations avec l'ensemble du groupe Domain Users ayant des droits d'administrateur local sur un ou plusieurs hôtes. Cela permettrait à un attaquant qui compromet N'IMPORTE QUEL compte (même un très peu privilégié) d'accéder à cet hôte en tant qu'administrateur local et potentiellement d'obtenir des données sensibles ou de voler des informations d'identification de compte de domaine hautement privilégiées de la mémoire si un autre utilisateur est connecté.

Il en va de même pour les droits Remote Desktop (RDP). Si de nombreux utilisateurs peuvent se connecter via RDP à une ou plusieurs machines, cela augmente le risque d'exposition de données sensibles ou d'attaques potentielles d'escalade de privilèges, conduisant à une compromission ultérieure.

***
