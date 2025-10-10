---
cover: ../../../.gitbook/assets/ad.png
coverY: 117.77066666666667
---

# Active Directory

***

### <mark style="color:red;">I. Qu'est-ce que l'Active Directory ?</mark>

> <mark style="background-color:yellow;">**Active Directory (AD)**</mark> <mark style="background-color:yellow;"></mark><mark style="background-color:yellow;">est un</mark> <mark style="background-color:yellow;"></mark><mark style="background-color:yellow;">**service d'annuaire**</mark> <mark style="background-color:yellow;"></mark><mark style="background-color:yellow;">développé par</mark> <mark style="background-color:yellow;"></mark><mark style="background-color:yellow;">**Microsoft**</mark> <mark style="background-color:yellow;"></mark><mark style="background-color:yellow;">pour gérer les utilisateurs, ordinateurs et ressources dans un réseau. Il permet deux fonctionnalités clés :</mark>

1. <mark style="color:orange;">**Identification**</mark> : Savoir qui ou quoi se connecte au réseau.
2. <mark style="color:orange;">**Authentification**</mark> : Vérifier l'identité d'un utilisateur ou d'une machine.

Exemple : Lorsqu'un utilisateur se connecte à un ordinateur de l'entreprise, son identifiant est vérifié via l'Active Directory.

***

### <mark style="color:red;">II. Les avantages d'un annuaire</mark>

**1. Administration centralisée :**\
L'AD centralise toutes les informations, rendant la gestion plus simple. On peut facilement gérer les utilisateurs, ordinateurs, et appliquer des **stratégies de groupe** pour automatiser des tâches.

**2. Authentification unique (Single Sign-On) :**\
Avec un seul identifiant et mot de passe, un utilisateur peut accéder à plusieurs ressources (serveurs, applications) sans avoir à se reconnecter.

Exemple : Une fois connecté à son PC, un employé peut accéder à des dossiers partagés, à une imprimante réseau ou à des logiciels sans avoir à entrer à nouveau ses identifiants.

**3. Identification des objets :**\
Chaque objet dans l'annuaire est unique. Cela permet de facilement retrouver et identifier un utilisateur ou un ordinateur dans un grand réseau.

***

### <mark style="color:red;">III. La structure de l'Active Directory</mark>

#### <mark style="color:green;">**A. Classes et Attributs**</mark>

Chaque objet dans Active Directory appartient à une **classe**. Par exemple :

* Un **utilisateur** est un objet de la classe "Utilisateur".
* Un **ordinateur** est un objet de la classe "Ordinateur".

Ces classes ont des **attributs** spécifiques, comme un nom ou une adresse email. Les unités d'organisation (OU) permettent de regrouper et organiser ces objets.

**Exemple :**\
Une entreprise peut regrouper tous ses employés dans des **OU** par département (RH, IT, Finance), facilitant la gestion.

#### <mark style="color:green;">**B. Le Schéma**</mark>

> <mark style="background-color:orange;">Le</mark> <mark style="background-color:orange;"></mark><mark style="background-color:orange;">**schéma**</mark> <mark style="background-color:orange;"></mark><mark style="background-color:orange;">d'Active Directory définit les classes et attributs disponibles. C'est un modèle de base qui peut être modifié pour répondre à des besoins spécifiques.</mark>

**Attention** : Les modifications du schéma affectent tout le réseau, il faut donc les faire avec précaution.

Exemple : Lorsque **Microsoft Exchange** (service de messagerie) est installé, il modifie le schéma pour ajouter ses propres classes et attributs.

**C. Partitions d'annuaire**

L'Active Directory est divisé en trois partitions logiques :

1. **Partition de schéma :** Contient les définitions des classes et attributs.
2. **Partition de configuration :** Garde la structure de la forêt (relations entre domaines et contrôleurs de domaine).
3. **Partition de domaine :** Stocke les informations spécifiques à un domaine (utilisateurs, groupes, ordinateurs).

{% hint style="warning" %}
Les partitions de l'annuaire Active Directory sont stockées dans la **base de données Active Directory** sur les **contrôleurs de domaine**. Ces partitions sont des divisions **logiques** au sein de la base de données qui permettent de mieux organiser et gérer les informations selon leur type et leur portée. Voyons plus en détail où et comment ces partitions sont gérées.



1\. **Partition de schéma** :

* **Contenu** : C'est ici que sont stockées les **définitions** de toutes les classes et attributs utilisés dans l'Active Directory. Cela inclut les définitions de ce qu’est un utilisateur, un groupe, un ordinateur, etc., ainsi que les types d’attributs qu’ils peuvent avoir.
*   **Où c'est stocké** : La partition de schéma est répliquée sur **tous les contrôleurs de domaine** de la forêt. Chaque DC (contrôleur de domaine) dans la forêt possède donc une copie de cette partition.

    > **Exemple** : Lorsque vous créez un nouvel utilisateur dans un domaine, la partition de schéma détermine les attributs obligatoires (nom, mot de passe) et facultatifs (téléphone, adresse) qu'un utilisateur doit avoir.



2\. **Partition de configuration** :

* **Contenu** : Elle contient les informations sur la **structure globale de la forêt**, y compris les relations entre domaines, les contrôleurs de domaine, et les sites. Elle est cruciale pour que l'Active Directory puisse répliquer les données correctement entre les contrôleurs de domaine dans la forêt.
*   **Où c'est stocké** : Comme la partition de schéma, la partition de configuration est également répliquée sur **tous les contrôleurs de domaine** de la forêt.

    > **Exemple** : La partition de configuration gère les relations de confiance entre les domaines. Si vous avez deux domaines, `domaineA` et `domaineB`, la partition de configuration stocke les informations sur cette relation.



3\. **Partition de domaine** :

* **Contenu** : Cette partition contient les informations **spécifiques à chaque domaine**, comme les utilisateurs, groupes, ordinateurs, et autres objets qui existent uniquement dans ce domaine.
*   **Où c'est stocké** : Contrairement aux partitions de schéma et de configuration, la partition de domaine n’est répliquée que sur les **contrôleurs de domaine** qui appartiennent à ce domaine particulier. Chaque domaine dans une forêt a sa propre partition de domaine, qui est répliquée uniquement entre les DC de ce domaine.

    > **Exemple** : Si vous avez un domaine `paris.corpA.local`, la partition de domaine stocke les objets spécifiques à ce domaine (utilisateurs, ordinateurs, groupes, etc.). Elle est répliquée uniquement entre les contrôleurs de domaine du domaine `paris.corpA.local`.



Où sont physiquement stockées ces partitions ?

Les partitions sont stockées physiquement dans la **base de données Active Directory**, qui est localisée dans le fichier **NTDS.DIT** sur les contrôleurs de domaine. Ce fichier est l'endroit où toutes les données Active Directory sont réellement sauvegardées. Il contient :

* Les objets AD (utilisateurs, ordinateurs, groupes, etc.)
* Les partitions (schéma, configuration, et domaine)
* Les informations nécessaires au bon fonctionnement et à la réplication de l'Active Directory.

Le fichier **NTDS.DIT** est situé, par défaut, sur le disque local du serveur dans un répertoire spécifique (souvent `C:\Windows\NTDS`).



**En résumé :**

* **Partition de schéma** et **partition de configuration** : Répliquées sur **tous les contrôleurs de domaine de la forêt**.
* **Partition de domaine** : Répliquée uniquement sur les **contrôleurs de domaine du domaine** auquel elle appartient.
* Toutes ces partitions sont stockées dans la base de données AD, dans le fichier **NTDS.DIT** sur chaque contrôleur de domaine.
{% endhint %}

**Exemple :**\
Dans une organisation avec plusieurs domaines (un par filiale, par exemple), chaque domaine a sa propre partition d'annuaire avec ses objets spécifiques.

***

### <mark style="color:red;">I. Du groupe de travail au domaine</mark>

Lorsqu'une entreprise utilise plusieurs ordinateurs, elle peut choisir de les organiser en **groupe de travail** ou en **domaine**. Voici les différences entre ces deux modèles.

<mark style="color:green;">**A. Modèle "Groupe de travail"**</mark>

* Chaque ordinateur a sa propre base d'utilisateurs appelée **base SAM** (Security Accounts Manager). Cela signifie que chaque machine a des comptes utilisateurs indépendants.
* Quand le nombre de machines augmente, ce modèle devient difficile à gérer : il faut créer des comptes pour chaque utilisateur sur chaque ordinateur.
* **Avantage :** Simple à mettre en place et ne nécessite pas de compétences techniques avancées.

**Exemple :** Si un utilisateur doit se connecter à 5 ordinateurs, il aura 5 comptes distincts, un sur chaque machine.

<mark style="color:green;">**B. Modèle "Domaine"**</mark>

* L'**Active Directory** centralise toutes les informations des utilisateurs, ordinateurs et groupes. Cela permet à un utilisateur d'accéder à n'importe quelle machine du domaine avec un seul compte.
* Chaque **contrôleur de domaine** possède une copie de l'annuaire Active Directory et se réplique avec les autres contrôleurs pour maintenir les données à jour.
* **Avantage :** Administration plus simple et gestion de la sécurité centralisée.

**Exemple :** Un utilisateur avec un seul compte peut se connecter à n'importe quelle machine du réseau.

***

### <mark style="color:red;">II. Les contrôleurs de domaine</mark>

#### <mark style="color:green;">**A. Qu'est-ce qu'un contrôleur de domaine ?**</mark>

> Un **contrôleur de domaine** est un serveur qui gère les utilisateurs, machines et ressources d'un domaine. Il :
>
> * Vérifie les identifiants (login, mot de passe).
> * Applique les stratégies de groupe (règles pour les utilisateurs et les ordinateurs).
> * Stocke une copie de l'annuaire Active Directory.

**Exemple :** Si vous vous connectez à un ordinateur dans un domaine, c'est le contrôleur de domaine qui vérifie votre mot de passe.

#### <mark style="color:green;">**B. Le fichier de base de données NTDS.dit**</mark>

Le fichier **NTDS.dit** est la base de données qui contient toutes les informations de l'Active Directory (utilisateurs, groupes, ordinateurs). Chaque contrôleur de domaine a une copie de ce fichier.

#### <mark style="color:green;">**C. La réplication des contrôleurs de domaine**</mark>

Pour garantir que les informations sont toujours à jour et disponibles, plusieurs contrôleurs de domaine sont souvent utilisés. Ils se **répliquent** entre eux pour partager les modifications (par exemple, l'ajout d'un nouvel utilisateur).

* Avant, on utilisait FRS pour la réplication.
* Maintenant, on utilise **DFSR**, un système plus performant.

**Exemple :** Si vous ajoutez un utilisateur sur un contrôleur de domaine, cette information est automatiquement copiée sur les autres contrôleurs.

***

### <mark style="color:red;">III. Concepts clés : Stratégie de groupe, Site, Forêt</mark>

#### <mark style="color:green;">**A. Stratégie de groupe (Group Policy)**</mark>

Une **stratégie de groupe** est un ensemble de règles appliquées aux utilisateurs ou ordinateurs dans un domaine. Cela permet de contrôler divers paramètres, comme la configuration réseau ou l'accès à certaines ressources.

**Exemple :** L'administrateur peut définir une stratégie qui interdit l'installation de logiciels sur les ordinateurs des employés.

#### <mark style="color:green;">**B. Site**</mark>

Un **site** dans l'Active Directory représente un emplacement physique où les ordinateurs sont connectés au réseau. Cela permet de mieux gérer les connexions réseau entre les différents lieux d'une organisation.

**Exemple :** Une entreprise avec des bureaux à Paris et à Lyon peut avoir deux sites dans son Active Directory pour gérer les connexions et la réplication entre ces deux emplacements.

#### <mark style="color:green;">**C. Forêt**</mark>

Une **forêt** est un ensemble de domaines qui partagent une structure d'annuaire commune. C'est la plus grande unité dans l'Active Directory et elle contient plusieurs domaines qui peuvent être gérés ensemble.

**Exemple :** Si une entreprise possède plusieurs divisions avec leurs propres domaines (ex. : domaine1.com, domaine2.com), ces domaines peuvent être regroupés dans une forêt pour centraliser la gestion.

***

## <mark style="color:red;">Active Directory - Domaines, Arbres et Forêts</mark>

***

### <mark style="color:blue;">**I. Symbolisation d’un Domaine**</mark>

* **Définition** : Un **domaine** est une unité administrative dans Active Directory (AD), regroupant différents types d'objets (utilisateurs, ordinateurs, groupes, etc.) sous une politique de sécurité commune.
* **Représentation** :
  * Sur les schémas, un domaine est souvent symbolisé par un **triangle**. Exemple : « it-connect.local ».
* **Structure des domaines** :
  * Un domaine est un conteneur hiérarchique, pouvant contenir des **Unités d’Organisation (UO)**, qui sont elles-mêmes des sous-conteneurs permettant d’organiser les objets.
* **Sous-domaines et domaines enfants** :
  * Une entreprise avec plusieurs sites géographiques peut organiser son domaine principal en **sous-domaines**. Exemple : « paris.it-connect.local » et « londres.it-connect.local » sont des **domaines enfants** du domaine racine « it-connect.local ».
* **Exemple visuel** :
  * Un domaine « it-connect.local » avec des sous-domaines pour différentes branches d'une entreprise.

***

### <mark style="color:blue;">**II. La Notion d’Arbre**</mark>

* **Définition** : Un **arbre** est un ensemble de domaines **hiérarchiquement liés**, partageant un **espace de nom continu**.
* **Caractéristiques principales** :
  * L'arbre commence par un **domaine racine**, puis se divise en **sous-domaines**, chaque sous-domaine représentant une **branche** de l'arbre.
  * Les domaines dans un même arbre partagent le même **espace de noms DNS**. Par exemple, dans un arbre avec le domaine racine « it-connect.local », les sous-domaines auront des noms contigus comme « paris.it-connect.local » ou « londres.it-connect.local ».
* **Exemple détaillé** :
  * Domaine racine : « it-connect.local »
  * Sous-domaines (branches) : « paris.it-connect.local », « londres.it-connect.local »
  * **Arbre** = Domaine racine + Sous-domaines, partageant un espace de nom DNS contigu.

***

### <mark style="color:blue;">**III. La Notion de Forêt**</mark>

* **Définition** : Une **forêt** est un ensemble de plusieurs **arbres** (domaines), qui peuvent être indépendants mais qui partagent certains services AD comme un **schéma d’annuaire commun**.
* **Caractéristiques principales** :
  * Chaque **arbre** dans une forêt a son propre **espace de noms DNS** distinct, mais les arbres partagent un **Catalogue Global** commun.
  * Les arbres dans une forêt peuvent **communiquer** entre eux grâce à des **relations d’approbation** (trusts).
* **Exemple** :
  * Arbre 1 : Domaine racine « it-connect.local » avec sous-domaines « paris.it-connect.local » et « londres.it-connect.local ».
  * Arbre 2 : Domaine racine « learn-online.local » avec sous-domaines « paris.learn-online.local », « rennes.learn-online.local », « dev.rennes.learn-online.local ».
  * **Forêt** = Ensemble de ces deux arbres, facilitant la gestion et les échanges entre domaines.
* **Utilité d'une forêt** :
  * **Schéma commun** : Tous les arbres dans la forêt partagent le même schéma d'annuaire.
  * **Catalogue global** : Permet la recherche et l’accès aux objets de n'importe quel domaine dans la forêt.
  * **Approvisionnement simplifié** : Un utilisateur de « paris.it-connect.local » peut accéder à des ressources dans « rennes.learn-online.local » selon les permissions définies.

***

### <mark style="color:blue;">**IV. Le Niveau Fonctionnel**</mark>

* **Définition** : Le **niveau fonctionnel** définit les **fonctionnalités** disponibles dans l'Active Directory pour un domaine ou une forêt, en fonction de la version de Windows Server utilisée.
* **Deux niveaux distincts** :
  1. **Niveau fonctionnel du domaine** : Limite les fonctionnalités disponibles uniquement dans un domaine spécifique.
  2. **Niveau fonctionnel de la forêt** : Affecte toutes les fonctionnalités au niveau de la forêt entière, incluant tous les domaines qu'elle contient.

<mark style="color:green;">**A. Un Niveau Fonctionnel, c’est quoi ?**</mark>

* **Explication** : Lors de la création d’un domaine, le **niveau fonctionnel** est déterminé par la version du **système d'exploitation** sur laquelle le domaine est installé (exemple : Windows Server 2012). Ce niveau définit les capacités et fonctionnalités disponibles.
* **Compatibilité** :
  * Le niveau fonctionnel permet de maintenir une compatibilité avec les contrôleurs de domaine utilisant des versions antérieures de Windows Server.

<mark style="color:green;">**B. Pourquoi Augmenter le Niveau Fonctionnel ?**</mark>

* **Avantages** :
  * Amélioration des **fonctionnalités** et **performances** en tirant parti des dernières évolutions des services Active Directory.
  * Obligation d’augmenter le niveau fonctionnel pour pouvoir intégrer des **nouveaux contrôleurs de domaine** fonctionnant sur des versions récentes de Windows Server.
* **Exemple** : Si un domaine est au niveau fonctionnel **Windows Server 2003**, vous ne pourrez pas ajouter de nouveaux contrôleurs de domaine sous **Windows Server 2012** ou supérieur.

<mark style="color:green;">**C. Portée d’un Niveau Fonctionnel**</mark>

* **Impact** :
  * Le **niveau fonctionnel de domaine** n’affecte que le domaine en question, tandis que le **niveau fonctionnel de la forêt** concerne l’ensemble des domaines contenus dans cette forêt.
  * **Mise à niveau** : Vous devez d’abord augmenter le niveau fonctionnel des **domaines** avant de pouvoir augmenter celui de la **forêt**.
* **Exemple** : Pour augmenter le niveau fonctionnel d'une forêt de « Windows Server 2008 » à « Windows Server 2012 », tous les domaines de cette forêt doivent également être au niveau « Windows Server 2012 ».

***

### <mark style="color:blue;">**V. Domaine, Arbre, Forêt : Conclusion et Récapitulatif**</mark>

1. **Domaine** : Unité de gestion principale dans Active Directory, regroupant des objets.
   * **Exemple** : « it-connect.local » avec ses objets (utilisateurs, ordinateurs).
2. **Arbre** : Ensemble de domaines hiérarchiquement liés partageant un espace de nom DNS.
   * **Exemple** : Domaine racine « it-connect.local » avec ses sous-domaines.
3. **Forêt** : Ensemble de plusieurs arbres partageant des services d’annuaire communs.
   * **Exemple** : Forêt regroupant les arbres « it-connect.local » et « learn-online.local ».
4. **Niveau Fonctionnel** : Définit les fonctionnalités disponibles dans AD, selon la version de Windows Server utilisée.

* **Exemple complet** :
  * Une entreprise possède deux branches, une à Paris et une à Londres, avec un domaine racine « it-connect.local » et des sous-domaines pour chaque branche. Elle acquiert une autre société avec un domaine racine « learn-online.local » et des sous-domaines pour ses succursales à Paris et Rennes. Les deux arborescences sont regroupées dans une forêt unique, facilitant l’administration, le partage des ressources et la gestion des accès utilisateurs entre les entités.

{% hint style="warning" %}
<mark style="color:green;">**Détails de chaque concept :**</mark>

**1. Domaine :**

* Un **domaine** est une unité logique dans laquelle les utilisateurs, ordinateurs et autres objets AD sont regroupés pour faciliter la gestion et la sécurité.
*   Bien qu'un **domaine** soit une entité logique, il repose sur un ou plusieurs **contrôleurs de domaine** (DC) pour fonctionner. Le **contrôleur de domaine** est un serveur physique (ou virtuel) qui stocke la base de données Active Directory et gère les demandes d'authentification et de validation des objets du domaine.

    > **Exemple :** `paris.corpA.local` est un domaine, mais les **contrôleurs de domaine** sont les serveurs qui exécutent les services AD pour ce domaine.

**2. Arbre (Tree) :**

* Un **arbre** est une hiérarchie de domaines qui partagent un **espace de noms DNS contigu**.
* C'est un concept logique qui regroupe plusieurs domaines sous une même racine. Par exemple, `corpA.local`, `paris.corpA.local`, et `londres.corpA.local` peuvent former un **arbre**.
*   L’arbre n'a pas de représentation physique. Ce sont les **contrôleurs de domaine** qui stockent les données de ces domaines et gèrent les communications entre eux.

    > **Exemple :** Un arbre avec un domaine racine `corpA.local` et deux sous-domaines `paris.corpA.local` et `londres.corpA.local`.

**3. Forêt (Forest) :**

* Une **forêt** est un ensemble de **plusieurs arbres**. C’est la plus grande unité logique dans Active Directory.
* Les arbres d’une forêt peuvent avoir des espaces de noms distincts, mais ils partagent des informations communes comme le **schéma AD** et le **catalogue global**.
*   Encore une fois, la forêt est une entité **logique**, mais elle s’appuie sur des serveurs réels (contrôleurs de domaine) pour fonctionner.

    > **Exemple :** Si vous avez deux arbres, l’un basé sur `corpA.local` et l’autre sur `corpB.local`, ces deux arbres peuvent coexister dans une **forêt**.

#### **Contrôleurs de domaine (DC)** :

* Les **contrôleurs de domaine** sont des serveurs réels qui hébergent et gèrent les services Active Directory.
*   Chaque **contrôleur de domaine** contient une copie de la base de données AD (qui inclut les utilisateurs, groupes, et autres objets). Ils répondent aux requêtes d'authentification et de validation dans le domaine.

    > Un domaine peut avoir plusieurs **contrôleurs de domaine**, mais le domaine lui-même est une abstraction **logique** qui repose sur ces serveurs physiques.

#### Différence entre **logique** et **physique** :

* **Logique** : Domaine, arbre, forêt sont des structures qui servent à organiser et gérer les objets dans un réseau. Ils définissent la façon dont les ressources sont organisées et comment elles interagissent.
* **Physique** : Les **contrôleurs de domaine** (serveurs) sont les composants physiques ou virtuels qui hébergent ces structures logiques. Ils exécutent les services et stockent les données nécessaires pour que le domaine fonctionne.

#### En résumé :

* **Arbre**, **forêt**, et **domaine** sont des concepts logiques qui permettent d’organiser les utilisateurs, ordinateurs, et autres ressources.
* Les **contrôleurs de domaine** sont les serveurs physiques (ou virtuels) qui hébergent ces entités logiques et gèrent les opérations Active Directory.
{% endhint %}

Le concept de **forêt** dans Active Directory est avant tout une **structure logique**, mais il repose sur des informations stockées et gérées par les **contrôleurs de domaine** via des partitions spécifiques dans la base de données Active Directory.

***

### <mark style="color:blue;">Qui stocke les informations sur la forêt ?</mark>

Les informations sur la forêt, y compris sa configuration et ses relations entre domaines, sont principalement gérées dans la **partition de configuration**. Cette partition est répliquée sur **tous les contrôleurs de domaine** (DC) de la forêt, ce qui garantit que chaque DC a les informations nécessaires pour comprendre la structure de la forêt et interagir avec les autres domaines de la forêt.

#### Sous quelle forme les informations sur la forêt sont-elles stockées ?

Les informations sur la forêt sont stockées sous forme d’**objets et d’attributs** dans la base de données Active Directory. Ces informations incluent :

* **Relations entre les domaines** (qui fait partie de quel arbre, quelles sont les relations d'approbation entre les domaines).
* **Configuration des sites** et des sous-réseaux (pour la réplication et la gestion des connexions réseau).
* **Rôles FSMO (Flexible Single Master Operations)** qui sont critiques pour l'administration de la forêt et des domaines.
* **Catalogue global** : C'est un sous-ensemble des données AD qui est répliqué sur certains DC pour faciliter la recherche d'objets dans toute la forêt.

#### Explication des partitions dans la forêt :

1. **Partition de configuration** :
   * Elle stocke toutes les informations sur la **structure de la forêt**, y compris les relations entre les domaines et les contrôleurs de domaine.
   * Par exemple, si vous avez deux domaines dans une forêt (`corpA.local` et `corpB.local`), la **partition de configuration** contient les informations sur la manière dont ces deux domaines sont reliés au sein de la même forêt, ainsi que la structure hiérarchique de la forêt.
2. **Partition de schéma** :
   * Le **schéma** est partagé à l’échelle de la forêt. Il définit les types d’objets que vous pouvez créer dans toute la forêt, comme les utilisateurs, ordinateurs, groupes, etc.
   * Chaque domaine de la forêt utilise le même schéma pour s'assurer que les objets sont uniformes dans toute la forêt.

***

### <mark style="color:blue;">Rôle des</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**contrôleurs de domaine**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">dans la gestion de la forêt :</mark>

Les **contrôleurs de domaine** sont les serveurs physiques ou virtuels qui hébergent les partitions et stockent les informations de l’Active Directory. Chaque **DC** dans une forêt détient les informations sur :

* **La partition de schéma** (partagée pour toute la forêt).
* **La partition de configuration** (partagée également pour toute la forêt).
* **La partition de domaine**, qui est spécifique au domaine du contrôleur de domaine.

Les contrôleurs de domaine communiquent entre eux via la **réplication AD** pour s’assurer que les données restent à jour dans l’ensemble de la forêt et des domaines.

#### Comment la forêt est-elle représentée dans Active Directory ?

La forêt elle-même n’a pas de forme physique. Elle est simplement un **concept organisationnel** qui permet de relier plusieurs **arbres** ou **domaines** ensemble, sous une même administration. Cependant, les informations qui définissent la forêt sont stockées dans des objets AD spécifiques et répliquées sur tous les contrôleurs de domaine dans les partitions **schéma** et **configuration**.

#### Exemple de forêt :

Imaginons une forêt avec deux arbres :

* **Arbre A** : `corpA.local` avec des sous-domaines `paris.corpA.local` et `londres.corpA.local`.
* **Arbre B** : `corpB.local` avec des sous-domaines `newyork.corpB.local` et `tokyo.corpB.local`.

La **partition de configuration** sur tous les contrôleurs de domaine de la forêt contiendra des informations sur les relations entre ces deux arbres, les domaines qui en font partie, et les relations d’approbation qui permettent aux utilisateurs de ces domaines d’interagir.

{% hint style="info" %}
sur les objets Active Directory dans une **forêt**. Il permet de **rechercher rapidement** des objets (utilisateurs, groupes, ordinateurs, etc.) dans n’importe quel domaine de la forêt, même si les informations complètes sur ces objets ne sont pas disponibles sur le contrôleur de domaine local. C’est un mécanisme essentiel pour améliorer la **recherche et la localisation des ressources** dans une grande infrastructure Active Directory.



Détails du **catalogue global** :

1. **Contenu** :
   * Il contient un **sous-ensemble des attributs** de chaque objet dans la forêt.
   * Par exemple, pour un utilisateur, il stocke des informations importantes comme le nom d'utilisateur, l'adresse e-mail et le numéro de téléphone. Cependant, il ne contient pas tous les attributs d'un utilisateur (comme le mot de passe, par exemple). Seules les données souvent utilisées pour la recherche sont incluses dans le catalogue global.
2. **Objectif** :
   * Le catalogue global permet de **rechercher** des objets dans toute la forêt sans avoir à contacter tous les contrôleurs de domaine des différents domaines.
   * Lorsque vous faites une recherche dans Active Directory, comme la recherche d'un utilisateur, d'un groupe ou d'une imprimante, la requête est envoyée au serveur **catalogue global**, qui a les informations nécessaires pour localiser ces objets dans n'importe quel domaine de la forêt.
3. **Où est-il stocké ?**
   * Le catalogue global est stocké sur des serveurs spécifiques appelés **serveurs de catalogue global**. Ces serveurs sont des **contrôleurs de domaine** qui ont été configurés pour jouer ce rôle. Tous les contrôleurs de domaine ne sont pas automatiquement des serveurs de catalogue global, mais plusieurs DC peuvent être configurés comme tels pour des raisons de **tolérance de panne** et de **performance**.
4. **Fonctionnement** :
   * Les **requêtes LDAP** (Lightweight Directory Access Protocol), qui sont des recherches d'objets dans l'Active Directory, passent souvent par le catalogue global.
   * Si un utilisateur dans le domaine **A** souhaite rechercher un utilisateur dans le domaine **B**, le serveur de catalogue global renverra l'information sans avoir besoin de consulter directement les contrôleurs de domaine du domaine **B**. Cela réduit le trafic réseau et améliore les temps de réponse.
5. **Partage de données entre domaines** :
   * Le catalogue global joue un rôle essentiel dans le **partage d'informations** entre les domaines d'une forêt.
   * Par exemple, un utilisateur du domaine **paris.corpA.local** peut chercher une ressource située dans le domaine **londres.corpB.local**, et le catalogue global permettra de **localiser** cet objet sans qu'il soit nécessaire d'interroger directement les contrôleurs de domaine dans chaque domaine de la forêt.



Exemple de fonctionnement :

Supposons que vous ayez deux domaines dans une forêt : `corpA.local` et `corpB.local`. Si un utilisateur de `corpA.local` cherche un autre utilisateur qui se trouve dans `corpB.local`, cette recherche se fait via un serveur de catalogue global. Le **serveur de catalogue global** a déjà un sous-ensemble des attributs de l’utilisateur de `corpB.local`, il peut donc retourner rapidement les informations requises sans interroger directement les contrôleurs de domaine du domaine **corpB.local**.



Rôle du **catalogue global** dans l’authentification :

Le **catalogue global** est aussi essentiel pour certaines opérations d'**authentification**. Par exemple, lors de la **connexion** d’un utilisateur à un domaine, si cet utilisateur est membre d’un groupe universel qui se trouve dans un autre domaine, le catalogue global sera interrogé pour valider cette appartenance. Cela permet à l’Active Directory de vérifier les permissions au sein de plusieurs domaines, rendant ainsi possible une gestion centralisée.



**En résumé** :

* Le **catalogue global** contient un sous-ensemble des informations des objets de tous les domaines d'une forêt.
* Il est stocké sur des **serveurs de catalogue global**, qui sont des contrôleurs de domaine configurés pour jouer ce rôle.
* Il permet de **rechercher** et de **localiser** des objets à travers tous les domaines de la forêt, facilitant la recherche d’informations et réduisant le temps de réponse.
* Il est utilisé pour améliorer l'**authentification** et les recherches dans les grandes infrastructures Active Directory.
{% endhint %}

***

## <mark style="color:red;">Les protocoles LDAP, DNS et Kerberos</mark>

### <mark style="color:blue;">I. Le Protocole LDAP</mark>

<mark style="color:green;">**A. Qu’est-ce que le protocole LDAP ?**</mark>

* **LDAP (Lightweight Directory Access Protocol)** : Protocole permettant d’accéder et d’administrer des services d'annuaire distribués. Il est utilisé pour interroger et modifier les informations des utilisateurs, groupes, ordinateurs, etc., dans un annuaire comme Active Directory.
* Utilisation : Recherche, ajout, suppression, modification d'entrées dans l'annuaire.
* Communication sur le port **389 (TCP)**.
* **LDAPS (version sécurisée)** : Utilise SSL/TLS pour chiffrer les échanges. Communication sur le port **636**.

<mark style="color:green;">**B. Que contient l’annuaire LDAP ?**</mark>

* **Types d'objets** : Utilisateurs, ordinateurs, groupes, contrôleurs de domaine, imprimantes, stratégies de groupe, etc.
* Chaque objet appartient à une **classe** avec des **attributs** spécifiques.
  * Exemple pour un utilisateur : Nom, prénom, mot de passe, adresse e-mail, etc.

<mark style="color:green;">**C. Comment est structuré l’annuaire LDAP ?**</mark>

* **Structure hiérarchique** sous forme d’**arborescence** d'unités d'organisation (OU).
* Chaque objet a un **DN (Distinguished Name)**, son identifiant unique.
  * Exemple : `CN=Florian,OU=Salariés,DC=it-connect,DC=local`.
* **GUID (Identifiant global unique)** : Identifie chaque objet dans l'annuaire.

***

### <mark style="color:blue;">II. Le Protocole DNS</mark>

* **DNS (Domain Name System)** : Permet la résolution de noms de domaine en adresses IP.
* **Importance dans Active Directory** : Il est essentiel au bon fonctionnement d'AD pour localiser les contrôleurs de domaine et autres services.
* Lors de la création d’un domaine, une **zone DNS** est créée automatiquement avec plusieurs enregistrements :
  * Enregistrements pour localiser le **Primary Domain Controller (PDC)**.
  * Enregistrements pour les contrôleurs de domaine, serveurs KDC, catalogue global, etc.
* **Rôle dans l’authentification et l’accès** : Les clients utilisent DNS pour localiser les contrôleurs de domaine et d'autres ressources.

***

### <mark style="color:blue;">III. Le Protocole Kerberos</mark>

<mark style="color:green;">**A. Comment fonctionne le protocole Kerberos ?**</mark>

* **Kerberos** est un protocole d'authentification basé sur des tickets, utilisé dans les environnements Active Directory pour sécuriser l'accès aux ressources.
* Chaque **contrôleur de domaine** dispose d'un **KDC (Key Distribution Center)**.
  * **Authentication Service (AS)** : Délivre un **TGT (Ticket-Granting Ticket)** à l'utilisateur une fois qu'il est authentifié.
  * **Ticket-Granting Service (TGS)** : Émet des tickets spécifiques pour accéder à des ressources, sur présentation du TGT.
* **TGT** : Permet d'accéder aux services sans réauthentification. Valide pour une durée limitée (par exemple 10 heures).
* Les tickets sont chiffrés, garantissant la confidentialité et empêchant les attaques de type « man-in-the-middle ».

<mark style="color:green;">**B. Importance de Kerberos dans Active Directory**</mark>

* **Essentiel pour l’authentification** des utilisateurs et l'accès aux ressources du domaine.
* Si le KDC est indisponible, l'authentification échoue, rendant les ressources inaccessibles.
* **NTLM (protocole plus ancien)** peut être utilisé en cas d’échec de Kerberos, mais il est moins sécurisé.

<mark style="color:green;">**C. De quoi est composé un ticket Kerberos ?**</mark>

* Contient l’**identité de l'utilisateur**, une **clé de session** pour sécuriser les échanges, et une **durée de validité**.
* Les tickets délivrés par le TGS spécifient l'**identité du service** ou du serveur auquel l'utilisateur peut accéder.

***

## <mark style="color:red;">Les principaux attributs d’objets dans l’Active Directory</mark>

<mark style="color:green;">**I. Les principales classes d'objets**</mark>

Active Directory contient différentes classes d'objets qui sont des entités que l'on peut gérer. Voici les plus courantes :

| **Classe d'objet**                             | **Description**                                                                                |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Computer** (Ordinateur)                      | Représente les ordinateurs clients et serveurs du domaine.                                     |
| **Contact**                                    | Représente des contacts sans possibilité d’authentification.                                   |
| **Group** (Groupe)                             | Permet de regrouper des objets pour simplifier la gestion, comme les permissions.              |
| **Organizational-Unit** (Unité d'organisation) | Crée une structure hiérarchique pour organiser les objets.                                     |
| **User** (Utilisateur)                         | Représente les comptes d'utilisateurs permettant l'authentification et l'accès aux ressources. |

***

<mark style="color:green;">**II. Les identifiants uniques pour les objets**</mark>

Chaque objet dans Active Directory a des identifiants uniques pour garantir son unicité dans l'annuaire.

**A. DistinguishedName (DN)**

* Le **DN** est le chemin LDAP complet vers un objet dans l'annuaire.
  * Ex : `cn=Florian,ou=Salariés,dc=it-connect,dc=local`
* Il peut changer si l'objet est déplacé ou si une unité d'organisation est renommée.

**B. ObjectGUID**

* Un **GUID** (Globally Unique Identifier) est un identifiant unique pour chaque objet dans AD.
* Il est immuable et attribué à la création de l'objet. Il reste constant même si l'objet est déplacé.

**C. ObjectSID**

* Utilisé pour identifier de manière unique les objets de sécurité comme les utilisateurs et les groupes.
* L'attribut ne change pas si l'objet est déplacé au sein du domaine ou d'une forêt.

**D. sAMAccountName et UserPrincipalName (UPN)**

* **sAMAccountName** : Identifiant court de l'utilisateur, unique dans le domaine.
* **UserPrincipalName (UPN)** : Identifiant unique de l'utilisateur sous la forme `nom@domaine.com`.

***

### <mark style="color:purple;">**III. Les attributs indispensables dans Active Directory**</mark>

Voici les attributs essentiels à connaître dans Active Directory. Ces attributs peuvent être consultés ou modifiés via les outils d'administration ou PowerShell.

| **Attribut (schéma AD)**    | **Nom dans la console**                     | **Description**                                                  |
| --------------------------- | ------------------------------------------- | ---------------------------------------------------------------- |
| **sAMAccountName**          | Nom d’ouverture de session de l’utilisateur | Nom utilisé pour l'authentification sur le domaine.              |
| **UserPrincipalName (UPN)** | Nom d’ouverture de session de l’utilisateur | Identifiant unique de l'utilisateur sous forme d'adresse e-mail. |
| **description**             | Description                                 | Description de l’objet.                                          |
| **mail**                    | Adresse de messagerie                       | Adresse e-mail associée à l'objet.                               |
| **adminCount**              | -                                           | `1` pour un compte administrateur, `0` pour un compte non-admin. |
| **DisplayName**             | Nom complet                                 | Nom complet affiché pour cet utilisateur.                        |
| **givenName**               | Prénom                                      | Prénom de l’utilisateur.                                         |
| **logonCount**              | -                                           | Nombre de connexions réalisées par l’utilisateur.                |
| **accountExpires**          | Date d’expiration du compte                 | Date d’expiration du compte (peut être vide).                    |
| **ObjectSID**               | -                                           | Identifiant de sécurité unique d'un objet.                       |
| **pwdLastSet**              | -                                           | Date de la dernière modification du mot de passe.                |
| **userAccountControl**      | -                                           | Indique l'état du compte (activé, désactivé, etc.).              |

***

### <mark style="color:purple;">**IV. Utilisation avec PowerShell**</mark>

* PowerShell est souvent utilisé pour consulter et modifier les objets et attributs dans Active Directory.
*   Exemple de commande pour obtenir les informations d'un utilisateur :

    ```powershell
    Get-ADUser -Identity Florian -Properties DisplayName, sAMAccountName, UserPrincipalName, mail
    ```

***

#### Conclusion

Active Directory repose sur une hiérarchie d'objets avec des identifiants uniques (DN, ObjectGUID, ObjectSID). Les attributs varient selon les classes d'objets et permettent de gérer efficacement les utilisateurs, groupes, ordinateurs, et autres objets du domaine. Le sAMAccountName et l'UPN sont des identifiants essentiels pour l'authentification des utilisateurs.

{% hint style="info" %}
le terme **"container"** (ou conteneur en français) fait référence à une unité d'organisation ou à une structure dans l'annuaire Active Directory qui regroupe des objets.

Un **container** (conteneur) dans Active Directory est un objet spécial qui peut contenir d'autres objets tels que des utilisateurs, des groupes ou d'autres conteneurs. Contrairement à une **unité d'organisation** (OU), un conteneur n'est pas personnalisable en termes de délégation de droits ou d'organisation, mais il permet de structurer les objets pour les rendre accessibles et les regrouper.

Dans l'exemple donné, le **container "Builtin"** est une section spécifique dans Active Directory où sont stockés les **groupes intégrés** (Built-in). Ces groupes sont prédéfinis et permettent de gérer des rôles ou des permissions spécifiques, tels que :

* **Opérateurs de sauvegarde** : Pour gérer les sauvegardes et restaurations.
* **Utilisateurs du Bureau à distance** : Pour permettre les connexions à distance via RDP.

Le container **Builtin** est une sorte de "boîte" dans laquelle se trouvent ces groupes prédéfinis, et il est accessible via la console **Utilisateurs et ordinateurs Active Directory**.
{% endhint %}

***

## <mark style="color:red;">Les différents types de groupe de l’Active Directory</mark>

### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Qu’est-ce qu’un groupe dans Active Directory ?**</mark>

Un groupe dans Active Directory permet de regrouper plusieurs objets, comme des utilisateurs, des ordinateurs, ou d'autres groupes, au sein d’un même objet. Les groupes facilitent l’attribution de permissions et la gestion des accès aux ressources. Plutôt que de gérer les autorisations utilisateur par utilisateur, on attribue des permissions à un groupe, et tous les membres du groupe héritent de ces droits.

### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Pourquoi utiliser des groupes ?**</mark>

L’utilisation de groupes simplifie la gestion des droits :

* Exemple : Un dossier partagé « Comptabilité » doit être accessible à tout le service comptabilité. Plutôt que d’ajouter les permissions pour chaque utilisateur, un groupe « Comptabilité » est créé, et les utilisateurs du service comptabilité sont ajoutés à ce groupe.
* Cela permet une gestion plus souple : lorsqu’un utilisateur quitte ou change de service, il suffit de le retirer ou de l'ajouter à un autre groupe sans devoir modifier les permissions manuellement.

***

### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Les étendues de groupe**</mark>

Les étendues définissent la portée d’un groupe, c’est-à-dire où le groupe peut être utilisé dans l’environnement Active Directory.

**A. Domaine local**

* **Portée** : Utilisable uniquement dans le domaine où il a été créé.
* **Membres possibles** : Peut inclure des utilisateurs, ordinateurs, ou groupes avec une étendue locale, globale ou universelle.
* **Utilisation** : Contrôle l'accès aux ressources **uniquement au niveau du domaine local**.

**B. Globale**

* **Portée** : Utilisable dans le domaine local et dans les domaines ayant une relation d’approbation.
* **Membres possibles** : Utilisateurs ou groupes du domaine local.
* **Utilisation** : Contrôle l'accès aux ressources à travers plusieurs domaines dans une forêt ou dans des domaines approuvés.

**C. Universelle**

* **Portée** : Utilisable dans **tous les domaines de la forêt**.
* **Membres possibles** : Utilisateurs, ordinateurs, ou groupes provenant de n’importe quel domaine de la forêt.
* **Utilisation** : Contrôle l'accès aux ressources à l'échelle de toute la forêt Active Directory.

***

### <mark style="color:blue;">4.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Types de groupe**</mark>

**A. Groupe de sécurité**

* **Objectif** : Utilisé pour gérer les **autorisations d'accès** aux ressources comme les dossiers, imprimantes, etc.
* **Identifiant** : Chaque groupe de sécurité dispose d’un **identifiant de sécurité (SID)** pour permettre l'attribution des permissions.
* **Exemple** : Un groupe de sécurité "Comptabilité" est utilisé pour donner accès au dossier partagé "Comptabilité".

**B. Groupe de distribution**

* **Objectif** : Utilisé pour créer des listes de distribution pour l’envoi de courriers électroniques (ex. : pour un serveur de messagerie comme Exchange).
* **Pas d’identifiant de sécurité (SID)** : Ce groupe ne peut pas être utilisé pour contrôler l'accès aux ressources.
* **Exemple** : Un groupe de distribution "Marketing" est utilisé pour envoyer un e-mail à tous les membres du service marketing.

***

### <mark style="color:blue;">5.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Les groupes par défaut**</mark>

**A. Groupes intégrés ("Builtin")**

Ces groupes sont créés automatiquement lors de la création d’un domaine Active Directory. Ils offrent des autorisations administratives spécifiques.

* **Étendue** : Domaine local.
* **Exemples** :
  * **Administrateurs** : Accès complet à tous les objets dans le domaine.
  * **Opérateurs de sauvegarde** : Gèrent la sauvegarde et la restauration des données.
  * **Utilisateurs du Bureau à distance** : Permettent aux membres de se connecter à distance via RDP (Remote Desktop Protocol).

**B. Groupes spéciaux**

Ces groupes sont contrôlés uniquement par le système et regroupent des utilisateurs selon des critères spécifiques.

* **Exemples** :
  * **Tout le monde** : Regroupe tous les utilisateurs, authentifiés ou non.
  * **Utilisateurs authentifiés** : Regroupe uniquement les utilisateurs ayant une session active dans le domaine.

**C. Groupes prédéfinis**

Ces groupes existent par défaut dans tous les environnements Active Directory, mais contrairement aux groupes "Builtin", ils sont plus flexibles.

* **Exemples** :
  * **Admins du domaine** : Ont un accès administrateur complet sur tous les postes et serveurs du domaine.
  * **Administrateurs du schéma** : Ont les droits pour modifier le schéma Active Directory.

***

### <mark style="color:blue;">6.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Bonnes pratiques : méthode "AGDLP"**</mark>

AGDLP est une méthode d’organisation des permissions sur les ressources Active Directory :

* **A** = **Accounts** : Les utilisateurs sont regroupés en fonction de leur rôle ou service.
* **G** = **Global Groups** : Ces utilisateurs sont ajoutés à des groupes globaux.
* **DL** = **Domain Local Groups** : Les groupes globaux sont ajoutés à des groupes locaux au domaine.
* **P** = **Permissions** : Les permissions sont attribuées aux groupes locaux du domaine.

Cette approche facilite la gestion des permissions et réduit les erreurs lors de modifications à long terme.

***

### <mark style="color:blue;">7.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Conversion entre les types de groupes**</mark>

* Il est possible de convertir un **groupe de sécurité** en **groupe de distribution** et inversement, à condition que le niveau fonctionnel du domaine soit au minimum "Windows Server 2000 natif".

***
