# Introduction : CMD vs PowerShell

### <mark style="color:blue;">Introduction : CMD vs PowerShell</mark>

PowerShell est le successeur moderne de CMD (invite de commandes) sur Windows. Voici les différences principales :

#### <mark style="color:$success;">Comparaison CMD vs PowerShell</mark>

<table data-full-width="true"><thead><tr><th>Caractéristique</th><th>CMD</th><th>PowerShell</th></tr></thead><tbody><tr><td><strong>Langage</strong></td><td>Commandes Batch et CMD uniquement</td><td>Interprète Batch, CMD, cmdlets PowerShell et alias</td></tr><tr><td><strong>Sortie des commandes</strong></td><td>Texte uniquement</td><td>Objets structurés (plus puissant)</td></tr><tr><td><strong>Enchaînement</strong></td><td>Impossible de passer directement la sortie d'une commande à une autre</td><td>Passage d'objets entre commandes possible</td></tr><tr><td><strong>Exécution parallèle</strong></td><td>Une commande à la fois</td><td>Peut exécuter plusieurs commandes en parallèle</td></tr></tbody></table>

#### Pourquoi choisir PowerShell ?

PowerShell est essentiel pour :

* **Administrateurs système** : Automatisation des tâches quotidiennes
* **Professionnels de la sécurité** : Tests de pénétration et analyse
* **Gestion Windows** : Serveurs, Azure, Microsoft 365

**Cas d'usage courants :**

* Création de comptes utilisateurs Active Directory
* Gestion des permissions
* Installation de rôles serveur
* Automatisation de tâches répétitives
* Interaction avec Azure et le cloud

***

### <mark style="color:blue;">Accéder à PowerShell</mark>

#### Méthodes pour ouvrir PowerShell :

1. **Recherche Windows** : Tapez "PowerShell"
2. **Windows Terminal** : Application moderne permettant plusieurs interfaces
3. **PowerShell ISE** : Environnement de développement intégré (IDE)
4. **Depuis CMD** : Tapez `powershell.exe`

***

### <mark style="color:blue;">Comprendre le Prompt PowerShell</mark>

```powershell
PS C:\Users\htb-student>
```

* `PS` = PowerShell
* `C:\Users\htb-student` = Répertoire actuel
* `>` = Invite de commande

***

### <mark style="color:blue;">Commandes d'Aide Essentielles</mark>

#### <mark style="color:green;">1. Get-Help - Obtenir de l'aide</mark>

```powershell
Get-Help Test-Wsman
```

**Sortie :**

```
NAME
    Test-WSMan

SYNTAX
    Test-WSMan [[-ComputerName] <string>] [-Authentication {None | Default...}]
```

**Options utiles :**

```powershell
Get-Help Test-Wsman -Online    # Ouvre la documentation en ligne
Get-Help Test-Wsman -Examples  # Affiche des exemples
Get-Help Test-Wsman -Detailed  # Informations détaillées
Get-Help Test-Wsman -Full      # Documentation complète
```

#### <mark style="color:green;">2. Update-Help - Mettre à jour l'aide</mark>

```powershell
Update-Help
```

**Explication :** Télécharge les dernières documentations pour toutes les cmdlets.

***

### <mark style="color:blue;">Navigation dans le Système de Fichiers</mark>

#### 1. Get-Location - Où suis-je ?

```powershell
Get-Location
```

**Sortie :**

```
Path
----
C:\Users\DLarusso
```

**Explication :** Affiche le chemin complet du répertoire actuel.

***

#### 2. Get-ChildItem - Lister le contenu

```powershell
Get-ChildItem
```

**Sortie :**

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/26/2021  10:26 PM                .ssh
d-----         1/28/2021   7:05 PM                .vscode
d-r---         1/27/2021   2:44 PM                3D Objects
d-r---         9/18/2022  12:35 PM                Desktop
```

**Explication des colonnes :**

* `Mode` : Type (d = répertoire, - = fichier)
* `LastWriteTime` : Date de dernière modification
* `Length` : Taille en octets
* `Name` : Nom du fichier/dossier

***

#### 3. Set-Location - Changer de répertoire

```powershell
Set-Location .\Documents\
```

**ou avec chemin complet :**

```powershell
Set-Location C:\Users\DLarusso\Documents
```

**Explication :**

* `.\` = répertoire actuel
* `..\` = répertoire parent

***

#### 4. Get-Content - Afficher le contenu d'un fichier

```powershell
Get-Content Readme.md
```

**Sortie :**

```
# PowerShell

Welcome to the PowerShell GitHub Community!
PowerShell Core is a cross-platform automation tool...
```

**Explication :** Lit et affiche tout le contenu du fichier texte.

***

### <mark style="color:blue;">Commandes Avancées de Recherche</mark>

#### 1. Get-Command - Trouver des commandes

**Lister toutes les commandes :**

```powershell
Get-Command
```

**Filtrer par verbe :**

```powershell
Get-Command -Verb Get
```

**Sortie :**

```
Cmdlet          Get-Acl
Cmdlet          Get-Alias
Cmdlet          Get-AppLockerFileInformation
```

**Explication :** Trouve toutes les commandes commençant par "Get"

***

**Filtrer par nom (avec wildcard) :**

```powershell
Get-Command Get-*
```

**Explication :** `*` = caractère joker (n'importe quoi)

***

**Filtrer par nom (nom) :**

```powershell
Get-Command -Noun Windows*
```

**Sortie :**

```
Cmdlet          Add-WindowsCapability
Cmdlet          Add-WindowsDriver
Cmdlet          Disable-WindowsOptionalFeature
```

**Explication :** Trouve toutes les commandes dont le nom contient "Windows"

***

### <mark style="color:blue;">Historique des Commandes</mark>

#### 1. Get-History - Historique de session

```powershell
Get-History
```

**Sortie :**

```
 Id CommandLine
 -- -----------
  1 Get-Command
  2 clear
  3 get-command -verb set
  4 ipconfig /all
```

**Utilisation :**

```powershell
r 4    # Réexécute la commande n°4 (ipconfig /all)
```

***

#### <mark style="color:blue;">2. PSReadLine - Historique permanent</mark>

**Emplacement du fichier :**

```
C:\Users\[Utilisateur]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Afficher l'historique complet :**

```powershell
Get-Content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**Fonctionnalité de sécurité :** PSReadLine filtre automatiquement les entrées contenant :

* password
* asplaintext
* token
* apikey
* secret

***

### <mark style="color:blue;">Raccourcis Clavier Essentiels</mark>

| Raccourci   | Description                             |
| ----------- | --------------------------------------- |
| `CTRL+R`    | Recherche interactive dans l'historique |
| `CTRL+L`    | Effacer l'écran rapidement              |
| `Escape`    | Effacer la ligne actuelle               |
| `↑` / `↓`   | Naviguer dans l'historique              |
| `F7`        | Interface graphique de l'historique     |
| `Tab`       | Auto-complétion                         |
| `Shift+Tab` | Auto-complétion inverse                 |

***

### <mark style="color:blue;">Auto-complétion avec Tab</mark>

**Exemple :**

```powershell
Get-C[Tab]    # Affiche Get-ChildItem
Get-Ch[Tab]   # Cycle entre Get-ChildItem, Get-Checkbox, etc.
```

**Explication :** Tab complète automatiquement les commandes, chemins et paramètres.

***

### <mark style="color:blue;">Aliases - Raccourcis de Commandes</mark>

#### Voir tous les alias

```powershell
Get-Alias
```

**Sortie :**

```
CommandType     Name                  
-----------     ----                  
Alias           % -> ForEach-Object
Alias           ? -> Where-Object
Alias           cd -> Set-Location
Alias           cls -> Clear-Host
Alias           dir -> Get-ChildItem
Alias           ls -> Get-ChildItem
```

***

#### Créer un alias personnalisé

```powershell
Set-Alias -Name gh -Value Get-Help
```

**Utilisation :**

```powershell
gh Get-Command    # Équivaut à Get-Help Get-Command
```

***

### <mark style="color:blue;">Tableau des Alias Utiles</mark>

| Alias           | Commande Complète | Description                     |
| --------------- | ----------------- | ------------------------------- |
| `pwd`           | Get-Location      | Affiche le répertoire actuel    |
| `ls`            | Get-ChildItem     | Liste les fichiers et dossiers  |
| `dir`           | Get-ChildItem     | Même chose que ls               |
| `cd`            | Set-Location      | Change de répertoire            |
| `cat`           | Get-Content       | Affiche le contenu d'un fichier |
| `clear` / `cls` | Clear-Host        | Efface l'écran                  |
| `curl`          | Invoke-WebRequest | Télécharge des fichiers web     |
| `man`           | help              | Affiche l'aide                  |
| `type`          | Get-Content       | Affiche le contenu d'un fichier |
| `cp`            | Copy-Item         | Copie des fichiers              |
| `mv`            | Move-Item         | Déplace des fichiers            |
| `rm`            | Remove-Item       | Supprime des fichiers           |

***

### <mark style="color:blue;">Effacer l'Écran</mark>

```powershell
Clear-Host
# ou
clear
# ou
cls
```

**Explication :** Efface l'affichage sans supprimer les variables ou l'historique.

***

### <mark style="color:blue;">Exemples Pratiques Complets</mark>

#### Exemple 1 : Navigation de base

```powershell
# Où suis-je ?
Get-Location

# Que contient ce dossier ?
Get-ChildItem

# Aller dans Documents
Set-Location .\Documents

# Vérifier la nouvelle position
Get-Location
```

***

#### Exemple 2 : Recherche de commandes

```powershell
# Trouver toutes les commandes "Get"
Get-Command -Verb Get

# Trouver les commandes liées à Process
Get-Command -Noun Process

# Obtenir de l'aide sur une commande
Get-Help Get-Process -Examples
```

***

#### Exemple 3 : Manipulation de fichiers

```powershell
# Lister les fichiers .txt
Get-ChildItem *.txt

# Lire un fichier
Get-Content monfichier.txt

# Copier un fichier
Copy-Item source.txt destination.txt

# Supprimer un fichier
Remove-Item fichier.txt
```

***

### <mark style="color:blue;">Conseils Importants</mark>

1. **Ne mémorisez pas toutes les commandes** - Comprenez les concepts
2. **Utilisez Tab** - L'auto-complétion est votre meilleur ami
3. **Get-Help est essentiel** - Consultez toujours l'aide
4. **Pratiquez régulièrement** - La mémorisation vient avec l'usage
5. **PowerShell log tout** - Attention lors de tests de sécurité

***

### <mark style="color:blue;">Convention de Nommage</mark>

PowerShell utilise la convention **Verbe-Nom** :

* `Get-Process` : Obtenir les processus
* `Set-Location` : Définir l'emplacement
* `Remove-Item` : Supprimer un élément
* `New-Item` : Créer un nouvel élément

**Verbes courants :** Get, Set, New, Remove, Add, Clear, Enable, Disable, Test, Invoke

***

### <mark style="color:blue;">Résumé des Commandes Principales</mark>

```powershell
# Aide
Get-Help [commande]
Update-Help

# Navigation
Get-Location           # Où suis-je ?
Set-Location [chemin]  # Changer de dossier
Get-ChildItem          # Lister le contenu

# Fichiers
Get-Content [fichier]  # Lire un fichier
Copy-Item              # Copier
Move-Item              # Déplacer
Remove-Item            # Supprimer

# Recherche
Get-Command            # Trouver des commandes
Get-Alias              # Voir les alias

# Historique
Get-History            # Historique de session
Clear-Host             # Effacer l'écran
```

***
