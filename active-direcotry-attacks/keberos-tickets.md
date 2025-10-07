---
cover: >-
  https://www.shutterstock.com/image-illustration/illustration-kerberos-mystical-creature-legendary-260nw-745336948.jpg
coverY: 81.5566037735849
layout:
  width: default
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# KEBEROS TICKETS

## <mark style="color:red;">Kerberos et les Types de Tickets</mark>

### <mark style="color:blue;">🎯 Qu'est-ce que Kerberos ?</mark>

**Kerberos** est un protocole d'authentification réseau basé sur des tickets, utilisé principalement dans les environnements **Active Directory** (AD). Il permet aux utilisateurs de s'authentifier sans envoyer leurs mots de passe sur le réseau.

**Port utilisé** : UDP 88

***

### <mark style="color:red;">🔑 Les Composants Clés</mark>

#### <mark style="color:blue;">1.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**KDC (Key Distribution Center)**</mark>

* Centre de distribution des tickets
* Présent sur chaque contrôleur de domaine
* Gère toutes les demandes de tickets Kerberos

#### <mark style="color:blue;">2.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**Compte KRBTGT**</mark>

* Compte spécial dans Active Directory
* Utilisé pour signer tous les tickets TGT
* Son hash est crucial pour la sécurité du domaine

#### <mark style="color:blue;">3.</mark> <mark style="color:blue;"></mark><mark style="color:blue;">**SPN (Service Principal Name)**</mark>

* Identifiant unique pour un service
* Format : `service/hôte[:port][/nom_service]`
* Exemple : `LDAP/dc1.domain.local`

***

### <mark style="color:red;">🎫 Les Différents Types de Tickets</mark>

#### <mark style="color:blue;">**TGT (Ticket Granting Ticket)**</mark>

<mark style="color:green;">**C'est quoi ?**</mark>

Le TGT est comme un **badge d'accès général** que vous obtenez au début de votre session. Il prouve votre identité auprès du KDC.

**Caractéristiques :**

* **Durée de vie** : Généralement 10 heures
* **Chiffré avec** : Le hash NTLM du compte KRBTGT
* **Stocké** : Dans la mémoire de votre session Windows
* **Usage** : Permet de demander des TGS pour accéder aux services

<mark style="color:green;">**Contenu d'un TGT :**</mark>

```
- Nom d'utilisateur
- Clé de session
- Date d'expiration
- PAC (Privilege Attribute Certificate) - vos droits/privilèges
```

***

#### <mark style="color:blue;">**TGS (Ticket Granting Service)**</mark>

<mark style="color:green;">**C'est quoi ?**</mark>

Le TGS est comme un **ticket spécifique** pour accéder à un service particulier (fichiers partagés, base de données, etc.).

**Caractéristiques :**

* **Durée de vie** : Variable selon le service
* **Chiffré avec** : Le hash NTLM du compte de service
* **Usage** : Permet d'accéder à UN service spécifique

<mark style="color:green;">**Contenu d'un TGS :**</mark>

```
- Nom d'utilisateur
- Clé de session du service
- Date d'expiration
- SPN du service ciblé
- PAC avec vos privilèges
```

***

### <mark style="color:red;">🔄 Le Processus d'Authentification Kerberos (Simplifié)</mark>

#### <mark style="color:blue;">**Étape 1 : Demande du TGT**</mark>

```
Utilisateur → KDC : "Je suis Bob, voici mon timestamp chiffré"
                     (chiffré avec le hash de Bob)
```

#### <mark style="color:blue;">**Étape 2 : Réception du TGT**</mark>

```
KDC → Utilisateur : "Voici ton TGT + une clé de session"
                     (TGT chiffré avec le hash KRBTGT)
```

#### <mark style="color:blue;">**Étape 3 : Demande d'un TGS**</mark>

```
Utilisateur → KDC : "Voici mon TGT, je veux accéder au service LDAP"
                     (envoie une copie du TGT)
```

#### <mark style="color:blue;">**Étape 4 : Réception du TGS**</mark>

```
KDC → Utilisateur : "Voici ton TGS pour LDAP"
                     (TGS chiffré avec le hash du service LDAP)
```

#### <mark style="color:blue;">**Étape 5 : Accès au Service**</mark>

```
Utilisateur → Service : "Voici mon TGS pour toi"
Service : "OK, accès autorisé !"
```

***

### <mark style="color:blue;">🎨 Schéma de Chiffrement (Codes Couleurs)</mark>

Les messages Kerberos utilisent 3 types de chiffrement :

| Couleur  | Type de Hash               | Usage                                  |
| -------- | -------------------------- | -------------------------------------- |
| 🔵 BLEU  | Hash NTLM de l'utilisateur | Chiffre les messages utilisateur ↔ KDC |
| 🟡 JAUNE | Hash NTLM du KRBTGT        | Chiffre les TGT                        |
| 🔴 ROUGE | Hash NTLM du service       | Chiffre les TGS                        |

***

### <mark style="color:red;">🎭 Tickets Forgés (Attaques)</mark>

#### <mark style="color:blue;">**Golden Ticket**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">🥇</mark>

**C'est quoi ?**

Un **faux TGT** créé en utilisant le hash du compte KRBTGT.

**Pourquoi c'est dangereux ?**

* Permet de créer des tickets pour N'IMPORTE QUEL utilisateur
* Donne un accès complet au domaine
* Persist même après changement de mot de passe

<mark style="color:green;">**Comment ça marche ?**</mark>

```
1. Attaquant obtient le hash KRBTGT
2. Forge un TGT pour "Administrateur" (ou n'importe qui)
3. Utilise ce TGT pour accéder à tout
```

**Durée de vie :**

* Peut être valide jusqu'à 10 ans !
* Nécessite de changer le mot de passe KRBTGT 2 fois pour l'invalider

***

#### <mark style="color:blue;">**Silver Ticket**</mark> <mark style="color:blue;"></mark><mark style="color:blue;">🥈</mark>

**C'est quoi ?**

Un **faux TGS** créé en utilisant le hash d'un compte de service spécifique.

**Différence avec Golden Ticket :**

* Plus limité (un seul service)
* Ne contacte PAS le KDC
* Plus difficile à détecter

<mark style="color:green;">**Comment ça marche ?**</mark>

```
1. Attaquant obtient le hash du service (ex: SQL)
2. Forge un TGS pour ce service
3. Accède directement au service sans passer par le KDC
```

**Durée de vie :**

* Généralement quelques heures
* Invalidé quand le compte de service change son mot de passe

***

### <mark style="color:red;">⚔️ Attaques Courantes</mark>

#### <mark style="color:blue;">**Kerberoasting**</mark>

* **Cible** : Comptes de service avec SPN
* **Méthode** : Demande un TGS, puis craque le hash offline
* **Protection** : Mots de passe forts pour les comptes de service

#### <mark style="color:blue;">**AS-REP Roasting**</mark>

* **Cible** : Comptes sans pré-authentification
* **Méthode** : Récupère un hash AS-REP, puis le craque
* **Protection** : Activer la pré-authentification pour tous

#### <mark style="color:blue;">**Pass-the-Ticket (PtT)**</mark>

* **Méthode** : Réutilise un ticket volé
* **Protection** : Limiter la durée de vie des tickets

***

### <mark style="color:blue;">📊 Tableau Comparatif des Tickets</mark>

| Caractéristique   | TGT         | TGS             | Golden Ticket   | Silver Ticket   |
| ----------------- | ----------- | --------------- | --------------- | --------------- |
| **Validé par**    | KDC         | KDC             | Aucun           | Aucun           |
| **Chiffré avec**  | Hash KRBTGT | Hash du service | Hash KRBTGT     | Hash du service |
| **Accès**         | Général     | Spécifique      | Général         | Spécifique      |
| **Durée typique** | 10h         | Variable        | 10 ans possible | Quelques heures |
| **Détectable**    | Oui         | Oui             | Difficile       | Très difficile  |

***

### <mark style="color:red;">🛡️ Commandes Rubeus Essentielles</mark>

#### <mark style="color:blue;">Générer un TGT</mark>

```bash
rubeus.exe asktgt /user:bob /password:Password123
```

#### <mark style="color:blue;">Générer un TGS</mark>

```bash
rubeus.exe asktgs /ticket:TGT_base64 /service:LDAP/dc.domain.local
```

#### <mark style="color:blue;">Voir les tickets</mark>

```bash
rubeus.exe triage
klist (commande Windows native)
```

#### <mark style="color:blue;">Injecter un ticket</mark>

```bash
rubeus.exe ptt /ticket:ticket_base64
```

#### <mark style="color:blue;">Créer un Golden Ticket</mark>

```bash
rubeus.exe golden /aes256:hash_krbtgt /user:admin /printcmd
```

#### <mark style="color:blue;">Créer un Silver Ticket</mark>

```bash
rubeus.exe silver /service:cifs/server /rc4:hash_service /user:admin
```

***

### <mark style="color:red;">🔍 Comment Identifier un Ticket ?</mark>

#### <mark style="color:blue;">Dans la mémoire (klist) :</mark>

```
Client: bob @ DOMAIN.LOCAL
Server: krbtgt/DOMAIN.LOCAL @ DOMAIN.LOCAL  ← C'est un TGT
```

```
Client: bob @ DOMAIN.LOCAL
Server: LDAP/dc.domain.local @ DOMAIN.LOCAL  ← C'est un TGS
```

***

### <mark style="color:red;">💡 Points Clés à Retenir</mark>

1. **TGT** = Badge général pour demander d'autres tickets
2. **TGS** = Ticket spécifique pour UN service
3. **Golden Ticket** = Faux TGT (accès total au domaine)
4. **Silver Ticket** = Faux TGS (accès à un service)
5. Les tickets sont stockés dans la **mémoire** de votre session
6. Kerberos utilise des **hashs** pour chiffrer, pas des mots de passe
7. Le **KRBTGT** est le compte le plus important du domaine

***
