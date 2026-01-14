# Fonctionnalité Active Directory

### <mark style="color:blue;">Rôles FSMO</mark>

<table data-full-width="true"><thead><tr><th width="557">Rôle</th><th>Description</th></tr></thead><tbody><tr><td><strong>Maître du schéma (Schema Master)</strong></td><td>Ce rôle gère la copie en lecture/écriture du schéma AD, qui définit tous les attributs pouvant s’appliquer à un objet dans AD.</td></tr><tr><td><strong>Maître de l’attribution de noms de domaine (Domain Naming Master)</strong></td><td>Gère les noms de domaine et garantit que deux domaines portant le même nom ne soient pas créés dans la même forêt.</td></tr><tr><td><strong>Maître RID (Relative ID Master)</strong></td><td>Le maître RID attribue des blocs de RID aux autres contrôleurs de domaine du domaine, qui peuvent être utilisés pour les nouveaux objets. Le maître RID permet de s’assurer que plusieurs objets ne se voient pas attribuer le même SID. Les SID des objets de domaine sont composés du SID du domaine combiné au numéro RID attribué à l’objet pour former un SID unique.</td></tr><tr><td><strong>Émulateur PDC (PDC Emulator)</strong></td><td>Le serveur détenant ce rôle est le contrôleur de domaine faisant autorité dans le domaine et répond aux demandes d’authentification, aux changements de mot de passe et gère les objets de stratégie de groupe (GPO). L’émulateur PDC maintient également l’heure au sein du domaine.</td></tr><tr><td><strong>Maître d’infrastructure (Infrastructure Master)</strong></td><td>Ce rôle traduit les GUID, SID et DN entre les domaines. Il est utilisé dans les organisations comportant plusieurs domaines dans une même forêt. Le maître d’infrastructure les aide à communiquer. Si ce rôle ne fonctionne pas correctement, les listes de contrôle d’accès (ACL) afficheront des SID au lieu de noms entièrement résolus.</td></tr></tbody></table>

Selon l’organisation, ces rôles peuvent être attribués à des contrôleurs de domaine spécifiques ou laissés par défaut lors de l’ajout d’un nouveau contrôleur de domaine.\
Des problèmes liés aux rôles FSMO entraîneront des difficultés d’authentification et d’autorisation au sein d’un domaine.

<mark style="color:green;">**📊 Récapitulatif**</mark>

<table data-full-width="true"><thead><tr><th>Rôle</th><th>Niveau</th><th>Nombre</th><th>Fonction principale</th></tr></thead><tbody><tr><td>Schema Master</td><td>Forêt</td><td>1</td><td>Modifie la structure AD</td></tr><tr><td>Domain Naming Master</td><td>Forêt</td><td>1</td><td>Gère les noms de domaines</td></tr><tr><td>RID Master</td><td>Domaine</td><td>1 par domaine</td><td>Distribue les numéros d'ID</td></tr><tr><td>PDC Emulator</td><td>Domaine</td><td>1 par domaine</td><td>Chef du domaine (auth, pwd, time)</td></tr><tr><td>Infrastructure Master</td><td>Domaine</td><td>1 par domaine</td><td>Traduit les références entre domaines</td></tr></tbody></table>

***

### <mark style="color:blue;">Niveaux fonctionnels de domaine et de forêt</mark>

Microsoft a introduit les **niveaux fonctionnels** pour déterminer les différentes fonctionnalités et capacités disponibles dans **Active Directory Domain Services (AD DS)** au niveau du domaine et de la forêt.<br>

Ils sont également utilisés pour spécifier quels systèmes d’exploitation Windows Server peuvent exécuter un contrôleur de domaine dans un domaine ou une forêt.

Cet article et cet article décrivent à la fois les niveaux fonctionnels de domaine et de forêt, de Windows 2000 natif à Windows Server 2012 R2.

#### <mark style="color:green;">Niveaux fonctionnels de domaine</mark>

<table data-full-width="true"><thead><tr><th width="280">Niveau fonctionnel du domaine</th><th width="491">Fonctionnalités disponibles</th><th>Systèmes d’exploitation des contrôleurs de domaine pris en charge</th></tr></thead><tbody><tr><td><strong>Windows 2000 natif</strong></td><td>Groupes universels pour groupes de distribution et de sécurité, imbrication des groupes, conversion de groupes (entre groupes de sécurité et de distribution), historique SID.</td><td>Windows Server 2008 R2, Windows Server 2008, Windows Server 2003, Windows 2000</td></tr><tr><td><strong>Windows Server 2003</strong></td><td>Outil de gestion de domaine Netdom.exe, introduction de l’attribut lastLogonTimestamp, conteneurs utilisateurs et ordinateurs bien connus, délégation contrainte, authentification sélective.</td><td>Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008, Windows Server 2003</td></tr><tr><td><strong>Windows Server 2008</strong></td><td>Prise en charge de la réplication DFS, prise en charge du chiffrement AES (AES 128 et AES 256) pour le protocole Kerberos, stratégies de mot de passe granulaires.</td><td>Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008</td></tr><tr><td><strong>Windows Server 2008 R2</strong></td><td>Garantie du mécanisme d’authentification, comptes de service gérés (Managed Service Accounts).</td><td>Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2</td></tr><tr><td><strong>Windows Server 2012</strong></td><td>Prise en charge KDC pour les revendications, l’authentification composée et le renforcement Kerberos.</td><td>Windows Server 2012 R2, Windows Server 2012</td></tr><tr><td><strong>Windows Server 2012 R2</strong></td><td>Protections supplémentaires pour les membres du groupe Utilisateurs protégés, stratégies d’authentification, silos de stratégies d’authentification.</td><td>Windows Server 2012 R2</td></tr><tr><td><strong>Windows Server 2016</strong></td><td>Carte à puce requise pour la connexion interactive, nouvelles fonctionnalités Kerberos et nouvelles protections des informations d’identification.</td><td>Windows Server 2019 et Windows Server 2016</td></tr></tbody></table>

Aucun nouveau niveau fonctionnel n’a été ajouté avec la sortie de Windows Server 2019.\
Cependant, le niveau fonctionnel **Windows Server 2008** est le minimum requis pour ajouter des contrôleurs de domaine Windows Server 2019 à un environnement.\
De plus, le domaine cible doit utiliser **DFS-R** pour la réplication de SYSVOL.

***

#### <mark style="color:green;">Niveaux fonctionnels de forêt</mark>

Les niveaux fonctionnels de forêt ont introduit plusieurs capacités clés au fil des années :

<table data-full-width="true"><thead><tr><th>Version</th><th>Capacités</th></tr></thead><tbody><tr><td><strong>Windows Server 2003</strong></td><td>Introduction de la relation d’approbation de forêt, du renommage de domaine, des contrôleurs de domaine en lecture seule (RODC), et plus encore.</td></tr><tr><td><strong>Windows Server 2008</strong></td><td>Tous les nouveaux domaines ajoutés à la forêt utilisent par défaut le niveau fonctionnel de domaine Server 2008. Aucune nouvelle fonctionnalité supplémentaire.</td></tr><tr><td><strong>Windows Server 2008 R2</strong></td><td>La Corbeille Active Directory permet de restaurer les objets supprimés lorsque AD DS est en fonctionnement.</td></tr><tr><td><strong>Windows Server 2012</strong></td><td>Tous les nouveaux domaines ajoutés à la forêt utilisent par défaut le niveau fonctionnel de domaine Server 2012. Aucune nouvelle fonctionnalité supplémentaire.</td></tr><tr><td><strong>Windows Server 2012 R2</strong></td><td>Tous les nouveaux domaines ajoutés à la forêt utilisent par défaut le niveau fonctionnel de domaine Server 2012 R2. Aucune nouvelle fonctionnalité supplémentaire.</td></tr><tr><td><strong>Windows Server 2016</strong></td><td>Gestion des accès privilégiés (PAM) à l’aide de Microsoft Identity Manager (MIM).</td></tr></tbody></table>

{% hint style="info" %}
<mark style="color:green;">**🏢 Analogie pour mieux comprendre**</mark>

Imaginez une entreprise multinationale :

Niveau fonctionnel de DOMAINE = Règles d'une filiale

* Chaque pays (domaine) peut avoir ses propres règles internes
* France peut avoir le niveau 2016
* USA peut avoir le niveau 2012 R2
* Ces règles affectent seulement les employés de cette filiale

Niveau fonctionnel de FORÊT = Règles du groupe entier

* C'est la politique générale qui s'applique à **toute l'entreprise**
* Affecte les relations entre les filiales
* Si la forêt est en 2012, TOUS les domaines doivent être au minimum 2012

***

<mark style="color:green;">**📊 Exemples de fonctionnalités pour voir la différence**</mark>

<mark style="color:orange;">**Fonctionnalités de DOMAINE (affectent les objets locaux)**</mark>

**Windows Server 2008 (domaine) :**

* **Stratégies de mot de passe granulaires** : définir des règles de mot de passe différentes pour différents groupes d'utilisateurs
* Cela affecte uniquement les utilisateurs de **ce domaine**

**Windows Server 2008 R2 (domaine) :**

* **Comptes de service gérés** : des comptes spéciaux pour les services
* Encore une fois, seulement dans **ce domaine**

***

<mark style="color:orange;">**Fonctionnalités de FORÊT (affectent la structure globale)**</mark>

**Windows Server 2003 (forêt) :**

* **Relations d'approbation de forêt** : permet de faire confiance à une autre forêt complète
* **Renommage de domaine** : changer le nom d'un domaine dans la forêt
* Cela affecte **toute la structure**, pas juste un domaine

**Windows Server 2008 R2 (forêt) :**

* **Corbeille Active Directory** : restaurer des objets supprimés
* Cette fonctionnalité fonctionne **à travers tous les domaines** de la forêt
{% endhint %}

***

### <mark style="color:blue;">Relations d’approbation (Trusts)</mark>

> Une <mark style="color:orange;">**relation d’approbation**</mark> est utilisée pour établir une authentification forêt-à-forêt ou domaine-à-domaine, permettant aux utilisateurs d’accéder à des ressources (ou d’administrer) un autre domaine en dehors de celui où réside leur compte.

Une relation d’approbation crée un lien entre les systèmes d’authentification de deux domaines.

#### <mark style="color:green;">Types de relations d’approbation</mark>

<table data-full-width="true"><thead><tr><th>Type de trust</th><th>Description</th></tr></thead><tbody><tr><td><strong>Parent-enfant</strong></td><td>Domaines au sein de la même forêt. Le domaine enfant a une relation d’approbation bidirectionnelle et transitive avec le domaine parent.</td></tr><tr><td><strong>Lien croisé (Cross-link)</strong></td><td>Relation d’approbation entre domaines enfants afin d’accélérer l’authentification.</td></tr><tr><td><strong>Externe</strong></td><td>Relation d’approbation non transitive entre deux domaines séparés dans des forêts distinctes qui ne sont pas déjà reliées par une relation de forêt. Ce type de trust utilise le filtrage SID.</td></tr><tr><td><strong>Racine d’arbre (Tree-root)</strong></td><td>Relation d’approbation bidirectionnelle et transitive entre un domaine racine de forêt et un nouveau domaine racine d’arbre. Elles sont créées par conception lors de la configuration d’un nouveau domaine racine d’arbre dans une forêt.</td></tr><tr><td><strong>Forêt</strong></td><td>Relation d’approbation transitive entre deux domaines racines de forêt.</td></tr></tbody></table>

#### <mark style="color:green;">Exemple de relations d’approbation</mark>

<figure><img src="../../../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

***

Les relations d’approbation peuvent être **transitives** ou **non transitives**.

* Une relation d’approbation **transitive** signifie que la confiance est étendue aux objets auxquels le domaine enfant fait confiance.
* Dans une relation d’approbation **non transitive**, seul le domaine enfant lui-même est approuvé.

Les relations d’approbation peuvent être configurées comme **unidirectionnelles** ou **bidirectionnelles**.

* Dans une relation bidirectionnelle, les utilisateurs des deux domaines peuvent accéder aux ressources.
* Dans une relation unidirectionnelle, seuls les utilisateurs du domaine approuvé peuvent accéder aux ressources du domaine approuvant, et non l’inverse. La direction de la confiance est opposée à la direction de l’accès.

***
