# RecycleBin Forensics

#### <mark style="color:green;">Description</mark>

Récupération de fichiers supprimés depuis la **Corbeille Windows** (`C:\$RECYCLE.BIN`).

***

#### <mark style="color:green;">Structure de la Corbeille 📂</mark>

```
C:\$RECYCLE.BIN\
└── S-1-5-21-DOMAIN-SID-RID\      ← SID de l'utilisateur
    ├── $IXXXXXX.ext              ← Métadonnées
    └── $RXXXXXX.ext              ← Contenu réel du fichier
```

**Exemple** :

```
C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103\
├── $IE2XMEG.7z    ← Métadonnées (148 bytes)
└── $RE2XMEG.7z    ← Fichier réel (30 MB)
```

***

#### <mark style="color:green;">Accès à la Corbeille 🔍</mark>

**PowerShell**

```powershell
# ⚠️ IMPORTANT : Utiliser des guillemets simples pour éviter l'expansion de $
cd 'C:\$RECYCLE.BIN'

# Lister (fichiers cachés)
ls -force

# Accéder au dossier d'un utilisateur
cd 'C:\$RECYCLE.BIN\S-1-5-21-...-1103'
```

**Sans guillemets simples** :

```powershell
cd C:\$RECYCLE.BIN
# PowerShell interprète $RECYCLE comme une variable vide
# Résultat : cd vers le home directory
```

***

#### <mark style="color:green;">Fichiers de métadonnées (</mark><mark style="color:green;">`$I`</mark><mark style="color:green;">) 📋</mark>

**Structure (Windows 10+)**

| Offset | Taille   | Type     | Description                |
| ------ | -------- | -------- | -------------------------- |
| 0      | 8 bytes  | Header   | Version (0x02 pour Win10+) |
| 8      | 8 bytes  | Int64 LE | Taille du fichier original |
| 16     | 8 bytes  | FILETIME | Date/heure de suppression  |
| 24     | 4 bytes  | Int32 LE | Longueur du nom de fichier |
| 28     | variable | UTF-16   | Chemin complet original    |

**Lecture manuelle avec PowerShell**

```powershell
# Charger le fichier
$bytes = [System.IO.File]::ReadAllBytes('C:\$RECYCLE.BIN\...\$IE2XMEG.7z')

# Extraire la taille du fichier (offset 8, 8 bytes)
$fileSize = [BitConverter]::ToInt64($bytes, 8)
Write-Host "Taille: $fileSize bytes"

# Extraire la date de suppression (offset 16, 8 bytes)
$timestamp = [BitConverter]::ToInt64($bytes, 16)
$deleteDate = [datetime]::FromFileTimeUtc($timestamp)
Write-Host "Supprimé le: $deleteDate"

# Extraire la longueur du nom (offset 24, 4 bytes)
$nameLength = [BitConverter]::ToInt32($bytes, 24)

# Extraire le chemin original (offset 28, UTF-16)
$originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $nameLength * 2)
Write-Host "Chemin original: $originalPath"
```

**Sortie** :

```
Taille: 30416987 bytes
Supprimé le: Tuesday, October 29, 2024 2:31:09 PM
Chemin original: C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z
```

#### <mark style="color:green;">Lecture via COM Object (méthode facile) 🎯</mark>

```powershell
# Créer un objet Shell
$shell = New-Object -com shell.application

# Accéder à la Corbeille (namespace 10)
$recycleBin = $shell.Namespace(10)

# Lister les fichiers
$recycleBin.items() | Format-Table Name, Path, Size, ModifyDate
```

**Sortie** :

```
Name                    Path                                           Size      ModifyDate
----                    ----                                           ----      ----------
wapt-backup-sunday.7z   C:\$RECYCLE.BIN\...\$RE2XMEG.7z               30416987  10/24/2024 8:16:29 PM
```

***

#### <mark style="color:green;">Récupération du fichier 💾</mark>

**Méthode 1 : Copie directe**

```powershell
# Le fichier $R contient les données réelles
Copy-Item 'C:\$RECYCLE.BIN\...\$RE2XMEG.7z' -Destination 'C:\Users\username\recovered.7z'
```

**Méthode 2 : Via SCP (Linux)**

```bash
# Depuis Kali
scp -k 'username@dc.domain.htb:C:/$RECYCLE.BIN/.../\$RE2XMEG.7z' recovered.7z
```

**⚠️ Attention** : Les `$` doivent être échappés avec `\$` en bash !

**Méthode 3 : PowerShell Restore**

```powershell
$item = ($shell.Namespace(10)).items() | Where-Object {$_.Name -eq "wapt-backup-sunday.7z"}
$item.InvokeVerb("Restore")
```

***

#### Analyse du fichier récupéré 🔬

```bash
# Vérifier le type
file recovered.7z
# Output : 7-zip archive data, version 0.4

# Extraire
7z x recovered.7z

# Lister le contenu sans extraire
7z l recovered.7z
```
