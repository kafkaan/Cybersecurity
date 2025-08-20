# Generic All

## <mark style="color:red;">🔐 Qu’est-ce que le droit “Generic ALL” ?</mark>

Dans **Active Directory**, les **autorisations et privilèges** déterminent les actions qu’un utilisateur, un groupe ou un ordinateur peut effectuer sur un **objet cible** (compte, groupe, unité organisationnelle, etc.).

Le droit **“Generic ALL”** est l’un des **plus puissants** car il accorde un **contrôle total sur l’objet cible**.

***

## <mark style="color:red;">✅ Ce que permet “Generic ALL” :</mark>

Un utilisateur ou groupe ayant ce droit peut :

* 🔧 **Modifier tous les attributs** de l’objet (ex : nom, SID, appartenances, etc.)
* 🔑 **Réinitialiser le mot de passe** d’un utilisateur
* 👥 **Ajouter ou supprimer des membres** d’un groupe
* 📤 **Déléguer le contrôle** de l’objet à d’autres utilisateurs
* 🗑️ **Supprimer** l’objet de l’annuaire AD

***

## <mark style="color:red;">⚠️ Impact en cas d’exploitation</mark>

Un attaquant qui obtient le droit “Generic ALL” sur un objet critique (par exemple, un compte **Administrateur du domaine** ou un **compte de service privilégié**) peut rapidement atteindre une **prise de contrôle complète du domaine** (domain dominance).

***

## <mark style="color:red;">🧨 Exploitation d’un droit “Generic ALL”</mark>

#### 1. 📌 **Identifier les cibles concernées**

Un attaquant commence par **repérer les objets** sur lesquels il dispose du droit “Generic ALL”.\
👉 Pour cela, il peut utiliser des outils comme :

* **BloodHound** (cartographie des relations AD)
* **PowerView** (énumération de privilèges via PowerShell)

Une fois les cibles identifiées, il choisit celles qui présentent **le plus d’impact** (ex : comptes à privilèges élevés).

***

#### 2. 🔄 **Réinitialiser un mot de passe**

Si le droit “Generic ALL” s’applique à un **compte utilisateur**, l’attaquant peut :

* Réinitialiser son mot de passe
* Se connecter avec ce nouveau mot de passe
* Obtenir les **droits associés à ce compte**

💥 Si c’est un compte **Domain Admin**, l’attaquant a alors un **contrôle total sur le domaine**.

***

#### 3. 👥 **Modifier les appartenances à des groupes**

Si “Generic ALL” est attribué à un **groupe**, l’attaquant peut :

* **S’ajouter lui-même** à un groupe à haut privilège (ex : Domain Admins, Enterprise Admins)
* Hériter instantanément des privilèges associés

***

#### 4. 🔁 **Déléguer le contrôle**

L’attaquant peut utiliser “Generic ALL” pour :

* Donner des droits à **d’autres utilisateurs malveillants**
* Déléguer des actions spécifiques pour **bypasser la détection**

***

#### 5. 🗑️ **Supprimer ou modifier des objets critiques**

Avec “Generic ALL”, l’attaquant peut :

* Supprimer des **comptes à privilèges** ou des **services critiques**
* Perturber l’infrastructure
* Créer des **portes dérobées** durables
