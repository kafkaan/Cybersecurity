# Structure d’Active Directory

***

### <mark style="color:red;">Structure d’Active Directory</mark>

> Active Directory (AD) est un <mark style="color:orange;">**service d’annuaire pour les environnements réseau Windows**</mark>.\
> Il s’agit d’une structure distribuée et hiérarchique qui permet la gestion centralisée des ressources d’une organisation, y compris&#x20;

* les utilisateurs
* les ordinateurs
* les groupes
* les périphériques réseau et les partages de fichiers,
* &#x20;les stratégies de groupe
* les serveurs et les postes de travail
* ainsi que les relations de confiance.

AD fournit des fonctions d’authentification et d’autorisation dans un environnement de domaine Windows.

Un service d’annuaire, tel qu’Active Directory Domain Services (AD DS), offre à une organisation des moyens de stocker les données de l’annuaire et de les rendre disponibles à la fois aux utilisateurs standards et aux administrateurs sur le même réseau.

AD DS stocke des informations telles que les noms d’utilisateur et les mots de passe et gère les droits nécessaires pour permettre aux utilisateurs autorisés d’accéder à ces informations.

***

Les failles et mauvaises configurations d’Active Directory peuvent souvent être utilisées pour obtenir un point d’appui (accès interne), se déplacer latéralement et verticalement dans un réseau, et obtenir un accès non autorisé à des ressources protégées telles que des bases de données, des partages de fichiers, du code source, et bien plus encore.

AD est essentiellement une grande base de données accessible à tous les utilisateurs du domaine, quel que soit leur niveau de privilège.

Un compte utilisateur AD basique, sans privilèges supplémentaires, peut être utilisé pour énumérer la majorité des objets contenus dans AD, y compris, mais sans s’y limiter :

* Ordinateurs du domaine
* Utilisateurs du domaine
* Informations sur les groupes du domaine
* Unités d’organisation (OU)
* Stratégie de domaine par défaut
* Niveaux fonctionnels du domaine
* Politique de mots de passe
* Objets de stratégie de groupe (GPO)
* Relations de confiance entre domaines
* Listes de contrôle d’accès (ACL)

***

Pour cette raison, nous devons comprendre comment Active Directory est configuré et les bases de son administration avant d’essayer de l’attaquer.\
Il est toujours plus facile de « casser » des choses lorsque nous savons déjà comment les construire.

***

{% hint style="info" %}
Active Directory est organisé sous forme d’une structure arborescente hiérarchique, avec une forêt au sommet contenant un ou plusieurs domaines, qui peuvent eux-mêmes avoir des sous-domaines imbriqués.
{% endhint %}

> <mark style="color:orange;">**Une forêt**</mark> est la frontière de sécurité au sein de laquelle tous les objets sont sous contrôle administratif.

Une forêt peut contenir plusieurs domaines, et un domaine peut inclure d’autres domaines enfants ou sous-domaines.

> <mark style="color:orange;">**Un domaine**</mark> est une structure dans laquelle les objets qu’il contient (utilisateurs, ordinateurs et groupes) sont accessibles.

Il possède de nombreuses unités d’organisation (OU) intégrées, telles que Domain Controllers, Users, Computers, et de nouvelles OU peuvent être créées selon les besoins.

Les OU peuvent contenir des objets et des sous-OU, ce qui permet l’attribution de différentes stratégies de groupe.

***

À un niveau très (simplifié), une structure AD peut ressembler à ceci :

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

<details>

<summary><mark style="color:green;"><strong>ETUDE GRAPHIQUE</strong></mark></summary>

ici, nous pouvons dire que INLANEFREIGHT.LOCAL est le domaine racine et qu’il contient les sous-domaines (qu’ils soient enfants ou racines d’arbre) ADMIN.INLANEFREIGHT.LOCAL, CORP.INLANEFREIGHT.LOCAL et DEV.INLANEFREIGHT.LOCAL, ainsi que les autres objets qui composent un domaine tels que les utilisateurs, les groupes, les ordinateurs, et plus encore, comme nous le verrons en détail ci-dessous.

</details>

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

***

Il est courant de voir plusieurs domaines (ou forêts) reliés entre eux par des relations de confiance dans les organisations qui effectuent de nombreuses acquisitions.

{% hint style="warning" %}
Il est souvent plus rapide et plus simple de créer une relation de confiance avec un autre domaine ou une autre forêt que de recréer de nouveaux utilisateurs dans le domaine actuel.
{% endhint %}

***

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><mark style="color:green;"><strong>GRAPHIQUE ETUDE</strong></mark></summary>

Le graphique ci-dessous montre deux forêts, INLANEFREIGHT.LOCAL et FREIGHTLOGISTICS.LOCAL.

La flèche à double sens représente une relation de confiance bidirectionnelle entre les deux forêts, ce qui signifie que les utilisateurs d’INLANEFREIGHT.LOCAL peuvent accéder aux ressources de FREIGHTLOGISTICS.LOCAL et inversement.

Nous pouvons également voir plusieurs domaines enfants sous chaque domaine racine.

Dans cet exemple, nous pouvons voir que le domaine racine fait confiance à chacun des domaines enfants, mais que les domaines enfants de la forêt A n’ont pas nécessairement de relations de confiance établies avec les domaines enfants de la forêt B.

Cela signifie qu’un utilisateur faisant partie de admin.dev.freightlogistics.local ne pourra PAS s’authentifier sur des machines du domaine wh.corp.inlanefreight.local par défaut, même si une relation de confiance bidirectionnelle existe entre les domaines de premier niveau inlanefreight.local et freightlogistics.local.

Pour autoriser une communication directe entre admin.dev.freightlogistics.local et wh.corp.inlanefreight.local, une autre relation de confiance devra être configurée.

</details>

***
