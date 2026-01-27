# Gestion des Fichiers et Dossiers

## <mark style="color:red;">Gestion des Fichiers et Dossiers</mark>

### <mark style="color:blue;">📋 Cmdlets Principales et Alias</mark>

<table data-full-width="true"><thead><tr><th>Commande</th><th>Alias</th><th>Description</th></tr></thead><tbody><tr><td><code>Get-Item</code></td><td><code>gi</code></td><td>Récupère un objet (fichier, dossier, registre, etc.)</td></tr><tr><td><code>Get-ChildItem</code></td><td><code>ls</code> / <code>dir</code> / <code>gci</code></td><td>Liste le contenu d'un dossier</td></tr><tr><td><code>New-Item</code></td><td><code>md</code> / <code>mkdir</code> / <code>ni</code></td><td>Crée de nouveaux objets (fichiers, dossiers)</td></tr><tr><td><code>Set-Item</code></td><td><code>si</code></td><td>Modifie les propriétés d'un objet</td></tr><tr><td><code>Copy-Item</code></td><td><code>copy</code> / <code>cp</code> / <code>ci</code></td><td>Duplique un élément</td></tr><tr><td><code>Rename-Item</code></td><td><code>ren</code> / <code>rni</code></td><td>Renomme un objet</td></tr><tr><td><code>Remove-Item</code></td><td><code>rm</code> / <code>del</code> / <code>rmdir</code></td><td>Supprime un objet</td></tr><tr><td><code>Get-Content</code></td><td><code>cat</code> / <code>type</code></td><td>Affiche le contenu d'un fichier</td></tr><tr><td><code>Add-Content</code></td><td><code>ac</code></td><td>Ajoute du contenu à un fichier</td></tr><tr><td><code>Set-Content</code></td><td><code>sc</code></td><td>Remplace tout le contenu d'un fichier</td></tr><tr><td><code>Clear-Content</code></td><td><code>clc</code></td><td>Efface le contenu sans supprimer le fichier</td></tr><tr><td><code>Compare-Object</code></td><td><code>diff</code> / <code>compare</code></td><td>Compare deux objets</td></tr></tbody></table>

***

### <mark style="color:blue;">🗂️ Navigation</mark>

#### <mark style="color:green;">Se localiser</mark>

```powershell
Get-Location
```

**Sortie :**

```
Path
----
C:\Users\MTanaka
```

#### <mark style="color:green;">Changer de répertoire</mark>

```powershell
cd Documents
```

***

### <mark style="color:blue;">📁 Création de Dossiers</mark>

#### <mark style="color:green;">Créer un dossier simple</mark>

```powershell
New-Item -Name "SOPs" -Type directory
```

**Sortie :**

```
    Directory: C:\Users\MTanaka\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         10/5/2022  12:20 PM                SOPs
```

#### <mark style="color:green;">Créer un dossier (avec alias)</mark>

```powershell
mkdir "Physical Sec"
```

**Sortie :**

```
    Directory: C:\Users\MTanaka\Documents\SOPs

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         10/5/2022   4:30 PM                Physical Sec
```

#### <mark style="color:green;">Lister le contenu d'un dossier</mark>

```powershell
Get-ChildItem
# ou simplement : ls
```

**Sortie :**

```
Directory: C:\Users\MTanaka\Documents\SOPs

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/5/2022   9:08 AM                Cyber Sec
d-----        11/5/2022   9:09 AM                Physical Sec
d-----        11/5/2022   9:08 AM                Training
```

***

### <mark style="color:blue;">📄 Création de Fichiers</mark>

#### <mark style="color:green;">Créer un fichier vide</mark>

```powershell
New-Item "Readme.md" -ItemType File
```

**Sortie :**

```powershell
Directory: C:\Users\MTanaka\Documents\SOPs

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/10/2022   9:12 AM              0 Readme.md
```

***

### <mark style="color:blue;">✏️ Manipulation du Contenu</mark>

#### Ajouter du contenu à un fichier

```powershell
Add-Content .\Readme.md "Title: Insert Document Title Here
Date: x/x/202x
Author: MTanaka
Version: 0.1 (Draft)"
```

#### Lire le contenu d'un fichier

```powershell
Get-Content .\Readme.md
# ou simplement : cat .\Readme.md
```

**Sortie :**

```
Title: Insert Document Title Here
Date: x/x/202x
Author: MTanaka
Version: 0.1 (Draft)
```

***

### <mark style="color:blue;">🔄 Renommer des Fichiers</mark>

#### Renommer un seul fichier

```powershell
Rename-Item .\Cyber-Sec-draft.md -NewName Infosec-SOP-draft.md
```

#### Renommer plusieurs fichiers (changement d'extension)

```powershell
Get-ChildItem -Path *.txt | Rename-Item -NewName {$_.name -replace ".txt",".md"}
```

**Avant :**

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/13/2022   1:05 PM              0 file-1.txt
-a----        10/13/2022   1:05 PM              0 file-2.txt
-a----        10/13/2022   1:06 PM              0 file-3.txt
-a----        10/13/2022   1:06 PM              0 file-4.txt
-a----        10/13/2022   1:06 PM              0 file-5.txt
```

**Après :**

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/13/2022   1:05 PM              0 file-1.md
-a----        10/13/2022   1:05 PM              0 file-2.md
-a----        10/13/2022   1:06 PM              0 file-3.md
-a----        10/13/2022   1:06 PM              0 file-4.md
-a----        10/13/2022   1:06 PM              0 file-5.md
```

***

### <mark style="color:blue;">🔐 Types de Permissions Windows</mark>

<table data-full-width="true"><thead><tr><th>Permission</th><th>Description</th></tr></thead><tbody><tr><td><strong>Full Control</strong></td><td>Contrôle total : lecture, écriture, modification, suppression, changement de permissions</td></tr><tr><td><strong>Modify</strong></td><td>Modification : lecture, écriture et suppression de fichiers/dossiers</td></tr><tr><td><strong>List Folder Contents</strong></td><td>Liste le contenu des dossiers et sous-dossiers (dossiers uniquement)</td></tr><tr><td><strong>Read and Execute</strong></td><td>Lecture et exécution de fichiers (.ps1, .exe, .bat, etc.)</td></tr><tr><td><strong>Write</strong></td><td>Écriture : création de nouveaux fichiers et sous-dossiers</td></tr><tr><td><strong>Read</strong></td><td>Lecture : visualisation du contenu des fichiers et dossiers</td></tr><tr><td><strong>Traverse Folder</strong></td><td>Permet d'accéder aux sous-dossiers sans accès au dossier parent</td></tr></tbody></table>

***

### <mark style="color:blue;">💡 Astuces</mark>

#### Utiliser le pipe (|) pour combiner des commandes

```powershell
Get-ChildItem -Path *.txt | Rename-Item -NewName {$_.name -replace ".txt",".md"}
```

#### Afficher l'arborescence des dossiers

```powershell
tree /F
```

#### Navigation avec espaces dans les noms

```powershell
cd '.\Physical Sec\'
```

***

### 🎯 Réponses aux Questions du Lab

1. **Quel Cmdlet a l'alias "cat" ?**
   * Réponse : `Get-Content`
2. **Quel Cmdlet peut créer de nouveaux fichiers et dossiers ?**
   * Réponse : `New-Item`
3. **Pratiquez la création, l'édition et la suppression de fichiers/dossiers**
   * Réponse : `COMPLETE`
