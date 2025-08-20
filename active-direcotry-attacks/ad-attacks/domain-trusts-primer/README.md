# Domain Trusts Primer

***

{% hint style="warning" %}
Les grandes entreprises établissent des relations de confiance entre domaines pour faciliter l'intégration après une acquisition, évitant ainsi la migration complète des objets. Cependant, ces relations peuvent introduire des failles de sécurité, notamment si un sous-domaine vulnérable est exploité comme point d’entrée. Ces trusts existent aussi entre entreprises partenaires ou divisions internes. Une mauvaise configuration peut offrir des opportunités aux attaquants, d'où l'importance de sécuriser ces relations dès leur création.

***

### <mark style="color:blue;">🌳</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Forêt, Domaine, Arbre : Explication et Différences**</mark>

#### 📌 **1. Qu'est-ce qu'un Domaine ?**

Un **domaine** est la **plus petite unité logique** dans Active Directory.\
👉 C'est un ensemble d'**utilisateurs, d'ordinateurs et de ressources** qui partagent **une base de données commune** et **une politique de sécurité commune**.

🔹 **Exemple de domaines** :

* `techcorp.local`
* `marketing.techcorp.local`
* `finance.techcorp.local`

Chaque domaine a son propre **contrôleur de domaine (DC)** qui gère l'authentification et les ressources.

***

#### 📌 **2. Qu'est-ce qu'un Arbre ?**

Un **arbre (Tree)** est un **ensemble de domaines liés** dans une structure hiérarchique qui **partagent un espace de noms commun**.\
👉 Tous les domaines d’un même arbre sont liés par des **relations de confiance transitives bidirectionnelles**.

🔹 **Exemple d’un arbre** :

* `techcorp.local`
  * `marketing.techcorp.local`
  * `finance.techcorp.local`
  * `support.techcorp.local`

Ici, **`techcorp.local` est le domaine racine**, et les autres (`marketing`, `finance`, `support`) sont des **sous-domaines** qui forment un **arbre de domaines**.

***

#### 📌 **3. Qu'est-ce qu'une Forêt ?**

Une **forêt (Forest)** est un **ensemble de plusieurs arbres** qui peuvent être **indépendants**, mais qui partagent une **configuration commune** (ex. : le même schéma AD).\
👉 C’est la **plus grande unité** dans Active Directory.

🔹 **Exemple d’une forêt** :

* **Premier arbre : `techcorp.local`**
  * `marketing.techcorp.local`
  * `finance.techcorp.local`
  * `support.techcorp.local`
* **Deuxième arbre : `softwaretech.local`**
  * `dev.softwaretech.local`
  * `test.softwaretech.local`

Dans cette **forêt**, les domaines `techcorp.local` et `softwaretech.local` **n'ont pas le même espace de noms**, mais ils font partie de la même **infrastructure Active Directory** et peuvent établir des **relations de confiance**.

***
{% endhint %}

<table data-header-hidden data-full-width="true"><thead><tr><th width="316"></th><th width="223"></th><th></th></tr></thead><tbody><tr><td><strong>Concept</strong></td><td><strong>Définition</strong></td><td><strong>Exemple</strong></td></tr><tr><td><strong>Domaine</strong></td><td>Une unité logique regroupant des utilisateurs et des ressources</td><td><code>techcorp.local</code></td></tr><tr><td><strong>Arbre</strong></td><td>Un ensemble de domaines qui partagent un même espace de noms</td><td><code>techcorp.local</code>, <code>marketing.techcorp.local</code>, <code>finance.techcorp.local</code></td></tr><tr><td><strong>Forêt</strong></td><td>Un ensemble d'arbres qui peuvent avoir des noms différents</td><td><code>techcorp.local</code> + <code>softwaretech.local</code></td></tr></tbody></table>

{% hint style="warning" %}
🎯 **Résumé avec une analogie simple**

Imagine que **Active Directory** est une entreprise géante 🌍 :

1. **Domaine** 🏠 → C'est une **filiale** de l'entreprise. Elle gère ses employés et ses ressources de façon indépendante.
2. **Arbre** 🌲 → C'est un **groupe de filiales** qui ont **un nom commun** (ex. : "TechCorp").
3. **Forêt** 🌳 → C'est l'**ensemble de toutes les filiales** (ex. : TechCorp + SoftwareTech). Même si elles ont des noms différents, elles peuvent collaborer.
{% endhint %}

***

## <mark style="color:red;">**Aperçu des relations de confiance de domaine**</mark>

Une relation de confiance est utilisée pour établir **l'authentification forêt-forêt ou domaine-domaine** (intra-domaine), ce qui permet aux utilisateurs d'accéder aux ressources dans (ou d'effectuer des tâches administratives dans) un autre domaine, en dehors du domaine principal où leur compte réside.\
Une relation de confiance crée un lien entre les systèmes d'authentification de deux domaines et peut permettre une communication soit unidirectionnelle, soit bidirectionnelle (à double sens).\
Une organisation peut créer divers types de relations de confiance :

* <mark style="color:orange;">**Parent-enfant :**</mark> Deux ou plusieurs domaines au sein de la même forêt. Le domaine enfant a une relation de confiance transitive bidirectionnelle avec le domaine parent, ce qui signifie que les utilisateurs dans le domaine enfant **corp.inlanefreight.local** pourraient s'authentifier dans le domaine parent **inlanefreight.local**, et vice-versa.
* <mark style="color:orange;">**Lien croisé :**</mark> Une relation de confiance entre des domaines enfants pour accélérer l'authentification.
* <mark style="color:orange;">**Externe :**</mark> Une relation de confiance non transitive entre deux domaines distincts dans des forêts séparées qui ne sont pas déjà reliées par une relation de confiance de forêt. Ce type de relation utilise le filtrage SID ou filtre les demandes d'authentification (par SID) ne provenant pas du domaine de confiance.
* <mark style="color:orange;">**Racine d'arbre (Tree-root) :**</mark> Une relation de confiance transitive bidirectionnelle entre un domaine racine de forêt et un nouveau domaine racine d'arbre. Elles sont créées par conception lorsque vous mettez en place un nouveau domaine racine d'arbre au sein d'une forêt.
* <mark style="color:orange;">**Forêt :**</mark> Une relation de confiance transitive entre deux domaines racine de forêt.
* <mark style="color:orange;">**ESAE :**</mark> Une forêt bastion utilisée pour gérer Active Directory.
* Les relations de confiance peuvent être **transitives** ou non **transitives**.
* Une relation de confiance transitive signifie que la confiance s'étend aux objets auxquels le domaine enfant fait confiance. Par exemple, supposons que nous avons trois domaines. Dans une relation transitive, si le Domaine A a une relation de confiance avec le Domaine B, et que le Domaine B a une relation de confiance transitive avec le Domaine C, alors le Domaine A fera automatiquement confiance au Domaine C.
* Dans une relation de confiance non transitive, le domaine enfant lui-même est le seul en qui l'on a confiance.

![image](https://academy.hackthebox.com/storage/modules/143/transitive-trusts.png)

Imaginez que la confiance entre domaines est comme la réception d’un colis à domicile. Dans une relation de confiance **transitive**, n’importe quel membre de votre foyer (forêt) peut accepter le colis en votre nom, alors que dans une relation **non transitive**, seul vous (le propriétaire) pouvez le réceptionner.

Les relations de confiance peuvent être **unidirectionnelles** (un domaine accède aux ressources d’un autre, mais pas l’inverse) ou **bidirectionnelles** (les deux domaines se font confiance mutuellement).

Ces configurations, souvent mal révisées, peuvent créer des failles de sécurité. Par exemple, lors d’une fusion-acquisition, une relation bidirectionnelle entre l’entreprise principale et l’entreprise acquise peut exposer le domaine principal à des attaques (comme le Kerberoasting) si la sécurité de l’entreprise acquise est insuffisante.

Il est donc essentiel de bien configurer et surveiller ces relations de confiance pour éviter des chemins d’attaque imprévus.

![image](https://academy.hackthebox.com/storage/modules/143/trusts-diagram.png)

***

### <mark style="color:red;">Enumerating Trust Relationships</mark>

We can use the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

<mark style="color:orange;">**Using Get-ADTrust**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```
{% endcode %}

The above output shows that our current domain `INLANEFREIGHT.LOCAL` has two domain trusts. The first is with `LOGISTICS.INLANEFREIGHT.LOCAL`, and the `IntraForest` property shows that this is a child domain, and we are currently positioned in the root domain of the forest. The second trust is with the domain `FREIGHTLOGISTICS.LOCAL,` and the `ForestTransitive` property is set to `True`, which means that this is a **forest trust or external trust**. We can see that both trusts are set up to be bidirectional, meaning that users can authenticate back and forth across both trusts. This is important to note down during an assessment. If we cannot authenticate across a trust, we cannot perform any enumeration or attacks across the trust.

Aside from using built-in AD tools such as the Active Directory PowerShell module, both PowerView and BloodHound can be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView, we can use the [Get-DomainTrust](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainTrust/) function to enumerate what trusts exist, if any.

<mark style="color:orange;">**Checking for Existing Trusts using Get-DomainTrust**</mark>

```powershell-session
PS C:\htb> Get-DomainTrust 

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

<mark style="color:orange;">**Using Get-DomainTrustMapping**</mark>

```powershell-session
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : FREIGHTLOGISTICS.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:08 PM
WhenChanged     : 2/27/2022 12:02:41 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
```

<mark style="color:orange;">**Checking Users in the Child Domain using Get-DomainUser**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```
{% endcode %}

Another tool we can use to get Domain Trust is `netdom`. The `netdom query` sub-command of the `netdom` command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.

<mark style="color:orange;">**Using netdom to query domain trust**</mark><mark style="color:orange;">r</mark>

```cmd-session
C:\htb> netdom query /domain:inlanefreight.local trust
Direction Trusted\Trusting domain                         Trust type
========= =======================                         ==========

<->       LOGISTICS.INLANEFREIGHT.LOCAL
Direct
 Not found

<->       FREIGHTLOGISTICS.LOCAL
Direct
 Not found

The command completed successfully.
```

<mark style="color:orange;">**Using netdom to query domain controllers**</mark>

```cmd-session
C:\htb> netdom query /domain:inlanefreight.local dc
List of domain controllers with accounts in the domain:

ACADEMY-EA-DC01
The command completed successfully.
```

<mark style="color:orange;">**Using netdom to query workstations and servers**</mark>

```cmd-session
C:\htb> netdom query /domain:inlanefreight.local workstation
List of workstations with accounts in the domain:

ACADEMY-EA-MS01
ACADEMY-EA-MX01      ( Workstation or Server )

SQL01      ( Workstation or Server )
ILF-XRG      ( Workstation or Server )
MAINLON      ( Workstation or Server )
CISERVER      ( Workstation or Server )
INDEX-DEV-LON      ( Workstation or Server )
...SNIP...
```

We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.

<mark style="color:orange;">**Visualizing Trust Relationships in BloodHound**</mark>

![image](https://academy.hackthebox.com/storage/modules/143/BH_trusts.png)

***
