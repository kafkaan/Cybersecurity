# Cmdlets et Modules

## <mark style="color:red;">Cmdlets et Modules</mark>&#x20;

***

### <mark style="color:blue;">1. Qu'est-ce qu'un Cmdlet ?</mark>

#### Définition

Un **cmdlet** est une commande à fonction unique qui manipule des objets dans PowerShell.

#### Structure : Verbe-Nom

```
Test-WSMan
  ↓     ↓
Verbe  Nom
```

#### Caractéristiques des Cmdlets

* **Séparés par un tiret (-)** : `Get-Command`, `Set-Location`
* **Écrits en C#** (pas en PowerShell) puis compilés
* **Suivent une convention claire** : Action + Objet

#### Exemples de Cmdlets Courants

| Cmdlet            | Verbe  | Nom        | Description           |
| ----------------- | ------ | ---------- | --------------------- |
| `Get-Process`     | Get    | Process    | Obtenir les processus |
| `Set-Location`    | Set    | Location   | Définir l'emplacement |
| `Test-Connection` | Test   | Connection | Tester une connexion  |
| `Remove-Item`     | Remove | Item       | Supprimer un élément  |

***

### <mark style="color:blue;">2. Qu'est-ce qu'un Module PowerShell ?</mark>

#### Définition

Un **module** est du code PowerShell structuré, facile à utiliser et à partager.

#### Composition d'un Module

Un module peut contenir :

* ✅ Cmdlets
* ✅ Fichiers de scripts
* ✅ Fonctions
* ✅ Assemblies (bibliothèques compilées)
* ✅ Ressources associées (manifestes, fichiers d'aide)

***

#### <mark style="color:$success;">Types de Fichiers de Module</mark>

**A. Fichier Manifest (.psd1)**

**Exemple : PowerSploit.psd1**

**Contenu typique :**

```powershell
@{
    ModuleVersion = '3.0.0.0'
    GUID = '12345678-1234-1234-1234-123456789012'
    Author = 'PowerShellMafia'
    Description = 'PowerSploit - Collection de modules pour tests de pénétration'
    PowerShellVersion = '2.0'
    FunctionsToExport = '*'
    CmdletsToExport = '*'
}
```

**Ce que contient un fichier .psd1 :**

* 📌 Référence au module à charger
* 📌 Numéros de version
* 📌 GUID (identifiant unique)
* 📌 Auteur du module
* 📌 Copyright
* 📌 Compatibilité PowerShell
* 📌 Modules et cmdlets inclus
* 📌 Métadonnées

***

**B. Fichier Script Module (.psm1)**

**Exemple : PowerSploit.psm1**

```powershell
Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer -and !('Tests','docs' -contains $_.Name) } | % { Import-Module $_.FullName -DisableNameChecking }
```

**Explication ligne par ligne :**

1. `Get-ChildItem $PSScriptRoot`
   * Liste tous les éléments du répertoire actuel du script
2. `| ? { $_.PSIsContainer -and !('Tests','docs' -contains $_.Name) }`
   * `?` = alias de `Where-Object`
   * Filtre pour garder uniquement les dossiers
   * Exclut les dossiers "Tests" et "docs"
3. `| % { Import-Module $_.FullName -DisableNameChecking }`
   * `%` = alias de `ForEach-Object`
   * Importe chaque module trouvé
   * `-DisableNameChecking` évite les erreurs de noms en double

***

### <mark style="color:blue;">3. Gestion des Modules</mark>

#### <mark style="color:green;">A. Voir les Modules Chargés</mark>

```powershell
Get-Module
```

**Sortie :**

```powershell
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment...}
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable...}
Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption...}
```

**Explication des colonnes :**

* `ModuleType` : Type (Script, Manifest, Binary)
* `Version` : Version du module
* `Name` : Nom du module
* `ExportedCommands` : Commandes exportées par le module

***

#### B. Lister Tous les Modules Disponibles

```powershell
Get-Module -ListAvailable
```

**Sortie :**

```powershell
Directory: C:\Users\tru7h\Documents\WindowsPowerShell\Modules

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.1.0      PSSQLite                            {Invoke-SqliteBulkCopy, Invoke-SqliteQuery...}


Directory: C:\Program Files\WindowsPowerShell\Modules

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     1.0.1      Microsoft.PowerShell.Operation.V... {Get-OperationValidation, Invoke-OperationValidation}
Binary     1.0.0.1    PackageManagement                   {Find-Package, Get-Package, Get-PackageProvider...}
Script     3.4.0      Pester                              {Describe, Context, It, Should...}
Script     1.0.0.1    PowerShellGet                       {Install-Module, Find-Module, Save-Module...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Set-PSReadLineKeyHandler...}
```

**Explication :**

* `-ListAvailable` affiche TOUS les modules installés
* Même ceux qui ne sont pas chargés dans la session actuelle
* Organisés par répertoire

***

#### C. Importer un Module

**Obtenir de l'Aide sur Import-Module**

```powershell
Get-Help Import-Module
```

**Sortie :**

```powershell
NAME
    Import-Module

SYNOPSIS
    Adds modules to the current session.

SYNTAX
    Import-Module [-Name] <System.String[]> [-Alias <System.String[]>] 
    [-ArgumentList <System.Object[]>] [-AsCustomObject] 
    [-CimNamespace <System.String>] [-CimResourceUri <System.Uri>] 
    [-Cmdlet <System.String[]>] [-DisableNameChecking] [-Force] 
    [-Function <System.String[]>] [-Global] [-MaximumVersion <System.String>] 
    [-MinimumVersion <System.Version>] [-NoClobber] [-PassThru] 
    [-Prefix <System.String>] [-RequiredVersion <System.Version>] 
    [-Scope {Local | Global}] [-Variable <System.String[]>] 
    [<CommonParameters>]
```

***

**Exemple Pratique : Importer PowerSploit**

**Avant l'importation :**

```powershell
PS C:\Users\htb-student\Desktop\PowerSploit> Get-NetLocalgroup
```

**Sortie (ERREUR) :**

```
Get-NetLocalgroup : The term 'Get-NetLocalgroup' is not recognized as the name of a cmdlet, 
function, script file, or operable program.
```

**Explication :** La commande n'est pas reconnue car le module n'est pas chargé.

***

**Importation du module :**

```powershell
PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1
```

**Pas de sortie = Succès !**

***

**Après l'importation :**

```powershell
PS C:\Users\htb-student\Desktop\PowerSploit> Get-NetLocalgroup
```

**Sortie :**

```powershell
ComputerName GroupName                           Comment
------------ ---------                           -------
WS01         Access Control Assistance Operators Members of this group can remotely query authorization...
WS01         Administrators                      Administrators have complete and unrestricted access...
WS01         Backup Operators                    Backup Operators can override security restrictions...
WS01         Cryptographic Operators             Members are authorized to perform cryptographic operations.
WS01         Distributed COM Users               Members are allowed to launch, activate and use Distributed COM...
WS01         Event Log Readers                   Members of this group can read event logs from local machine
WS01         Guests                              Guests have the same access as members of the Users group...
WS01         Hyper-V Administrators              Members of this group have complete and unrestricted access...
WS01         IIS_IUSRS                           Built-in group used by Internet Information Services.
WS01         Network Configuration Operators     Members can have some administrative privileges...
WS01         Performance Log Users               Members may schedule logging of performance counters...
WS01         Performance Monitor Users           Members can access performance counter data locally...
WS01         Power Users                         Power Users are included for backwards compatibility...
WS01         Remote Desktop Users                Members in this group are granted the right to logon remotely
WS01         Remote Management Users             Members can access WMI resources over management protocols...
WS01         Replicator                          Supports file replication in a domain
WS01         System Managed Accounts Group       Members of this group are managed by the system.
WS01         Users                               Users are prevented from making accidental system-wide changes...
```

**Explication :** Maintenant que le module est chargé, toutes ses fonctions sont disponibles !

***

#### D. Chemin des Modules par Défaut

```powershell
PS C:\Users\htb-student> $env:PSModulePath
```

**Sortie :**

```powershell
C:\Users\htb-student\Documents\WindowsPowerShell\Modules;
C:\Program Files\WindowsPowerShell\Modules;
C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

**Explication :**

* PowerShell cherche les modules dans ces 3 emplacements
* Séparés par des point-virgules (;)
* Les modules placés ici sont chargés automatiquement

***

### <mark style="color:blue;">4. Execution Policy (Politique d'Exécution)</mark>

#### <mark style="color:green;">A. Qu'est-ce que l'Execution Policy ?</mark>

⚠️ **Important :** Ce N'EST PAS une mesure de sécurité !

* C'est une protection contre l'exécution accidentelle de scripts
* Peut être facilement contournée
* Outil pour les administrateurs IT

***

#### <mark style="color:green;">B. Vérifier la Politique Actuelle</mark>

```powershell
PS C:\htb> Get-ExecutionPolicy
```

**Sortie :**

```
Restricted
```

**Signification :**

* `Restricted` = Aucun script ne peut s'exécuter
* `AllSigned` = Seulement les scripts signés
* `RemoteSigned` = Scripts locaux OK, scripts distants doivent être signés
* `Unrestricted` = Tous les scripts peuvent s'exécuter
* `Bypass` = Rien n'est bloqué
* `Undefined` = Aucune politique définie

***

#### <mark style="color:green;">C. Erreur d'Execution Policy</mark>

```powershell
PS C:\Users\htb-student\Desktop\PowerSploit> Import-Module .\PowerSploit.psd1
```

**Sortie (ERREUR) :**

```
Import-Module : File C:\Users\Users\htb-student\PowerSploit.psm1
cannot be loaded because running scripts is disabled on this system. 
For more information, see about_Execution_Policies at 
https:/go.microsoft.com/fwlink/?LinkID=135170.

At line:1 char:1
+ Import-Module .\PowerSploit.psd1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

**Explication :** La politique empêche l'exécution du script.

***

#### <mark style="color:green;">D. Changer la Politique d'Exécution (Global)</mark>

```powershell
PS C:\htb> Set-ExecutionPolicy Undefined
```

**Prompt de confirmation :**

```
Execution Policy Change
The execution policy helps protect you from scripts that you do not trust...
Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
```

**Vérification :**

```powershell
PS C:\htb> Get-ExecutionPolicy
```

**Sortie :**

```
Undefined
```

***

#### E. Test Après Changement

```powershell
PS C:\htb> Import-Module .\PowerSploit.psd1
PS C:\Users\htb> Get-Module
```

**Sortie :**

```
ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Check...}
Manifest   3.0.0.0    Microsoft.PowerShell.Security       {ConvertFrom-SecureString, Conver...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Vari...}
Script     3.0.0.0    PowerSploit                         {Add-Persistence, Add-ServiceDacl...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PS...}
```

**Explication :** PowerSploit est maintenant chargé avec succès !

***

#### <mark style="color:green;">F. Changer la Politique par Portée (MÉTHODE RECOMMANDÉE)</mark>

```powershell
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process
```

**Explication :**

* Change uniquement pour la session actuelle
* Revient à la normale quand on ferme PowerShell
* **Plus sûr** - pas de modification permanente
* **Meilleur pour les pentesters** - ne laisse pas de traces

***

**Vérifier toutes les portées :**

```powershell
PS C:\htb> Get-ExecutionPolicy -List
```

**Sortie :**

```
        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process          Bypass    ← Modifié temporairement
  CurrentUser       Undefined
 LocalMachine          Bypass
```

**Explication des portées :**

* `MachinePolicy` : Définie par stratégie de groupe (priorité max)
* `UserPolicy` : Définie par stratégie utilisateur
* `Process` : Session actuelle seulement ⭐ **RECOMMANDÉ**
* `CurrentUser` : Pour l'utilisateur actuel
* `LocalMachine` : Pour tous les utilisateurs de la machine

***

### <mark style="color:blue;">5. Voir les Commandes d'un Module</mark>

```powershell
PS C:\htb> Get-Command -Module PowerSploit
```

**Sortie :**

```
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           Invoke-ProcessHunter                               3.0.0.0    PowerSploit
Alias           Invoke-ShareFinder                                 3.0.0.0    PowerSploit
Alias           Invoke-ThreadedFunction                            3.0.0.0    PowerSploit
Alias           Invoke-UserHunter                                  3.0.0.0    PowerSploit
Alias           Request-SPNTicket                                  3.0.0.0    PowerSploit
Alias           Set-ADObject                                       3.0.0.0    PowerSploit
Function        Add-Persistence                                    3.0.0.0    PowerSploit
Function        Add-ServiceDacl                                    3.0.0.0    PowerSploit
Function        Find-AVSignature                                   3.0.0.0    PowerSploit
Function        Find-InterestingFile                               3.0.0.0    PowerSploit
Function        Find-LocalAdminAccess                              3.0.0.0    PowerSploit
Function        Find-PathDLLHijack                                 3.0.0.0    PowerSploit
Function        Find-ProcessDLLHijack                              3.0.0.0    PowerSploit
Function        Get-ApplicationHost                                3.0.0.0    PowerSploit
Function        Get-GPPPassword                                    3.0.0.0    PowerSploit
```

**Explication :**

* Liste toutes les fonctions et alias du module
* Type de commande (Alias, Function, Cmdlet)
* Version du module
* Source (quel module fournit cette commande)

***

### <mark style="color:blue;">6. PowerShell Gallery</mark>

#### A. Qu'est-ce que PowerShell Gallery ?

🌐 **PowerShell Gallery** = Dépôt central de modules PowerShell

* Créé par Microsoft
* Modules communautaires
* Scripts partagés
* Gratuit et public

**URL :** https://www.powershellgallery.com/

***

#### B. Module PowerShellGet

**Voir les commandes disponibles :**

```powershell
PS C:\htb> Get-Command -Module PowerShellGet
```

**Sortie :**

```
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Find-Command                                       1.0.0.1    PowerShellGet
Function        Find-DscResource                                   1.0.0.1    PowerShellGet
Function        Find-Module                                        1.0.0.1    PowerShellGet
Function        Find-RoleCapability                                1.0.0.1    PowerShellGet
Function        Find-Script                                        1.0.0.1    PowerShellGet
Function        Get-InstalledModule                                1.0.0.1    PowerShellGet
Function        Get-InstalledScript                                1.0.0.1    PowerShellGet
Function        Get-PSRepository                                   1.0.0.1    PowerShellGet
Function        Install-Module                                     1.0.0.1    PowerShellGet
Function        Install-Script                                     1.0.0.1    PowerShellGet
Function        New-ScriptFileInfo                                 1.0.0.1    PowerShellGet
Function        Publish-Module                                     1.0.0.1    PowerShellGet
Function        Publish-Script                                     1.0.0.1    PowerShellGet
Function        Register-PSRepository                              1.0.0.1    PowerShellGet
Function        Save-Module                                        1.0.0.1    PowerShellGet
Function        Save-Script                                        1.0.0.1    PowerShellGet
Function        Set-PSRepository                                   1.0.0.1    PowerShellGet
Function        Test-ScriptFileInfo                                1.0.0.1    PowerShellGet
Function        Uninstall-Module                                   1.0.0.1    PowerShellGet
Function        Uninstall-Script                                   1.0.0.1    PowerShellGet
Function        Unregister-PSRepository                            1.0.0.1    PowerShellGet
Function        Update-Module                                      1.0.0.1    PowerShellGet
Function        Update-ModuleManifest                              1.0.0.1    PowerShellGet
Function        Update-Script                                      1.0.0.1    PowerShellGet
Function        Update-ScriptFileInfo                              1.0.0.1    PowerShellGet
```

***

#### C. Rechercher un Module

```powershell
PS C:\htb> Find-Module -Name AdminToolbox
```

**Sortie :**

```
Version    Name                                Repository           Description
-------    ----                                ----------           -----------
11.0.8     AdminToolbox                        PSGallery            Master module for a collection of modules...
```

**Explication :**

* `Version` : Version actuelle du module
* `Name` : Nom du module
* `Repository` : PSGallery (PowerShell Gallery)
* `Description` : Description courte

***

**Recherche avec wildcard :**

```powershell
Find-Module -Name Admin*
```

**Explication :** Trouve tous les modules commençant par "Admin"

***

#### D. Installer un Module

**Méthode 1 : Installation directe**

```powershell
Install-Module -Name AdminToolbox
```

**Prompt de confirmation :**

```
Untrusted repository
You are installing the modules from an untrusted repository...
Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
```

***

**Méthode 2 : Chaînage avec Pipeline (Find + Install)**

```powershell
Find-Module -Name AdminToolbox | Install-Module
```

**Explication :**

* `Find-Module` cherche le module
* `|` (pipe) passe le résultat à la commande suivante
* `Install-Module` installe ce qui a été trouvé
* **Tout en une seule ligne !**

***

**Installation sans confirmation :**

```powershell
Install-Module -Name AdminToolbox -Force -Scope CurrentUser
```

**Options expliquées :**

* `-Force` : Pas de confirmation
* `-Scope CurrentUser` : Installe seulement pour l'utilisateur actuel (pas besoin de droits admin)

***

#### E. Vérifier les Modules Installés

```powershell
Get-InstalledModule
```

**Sortie :**

```
Version    Name                                Repository           InstalledDate
-------    ----                                ----------           -------------
11.0.8     AdminToolbox                        PSGallery            22/01/2026 14:35:12
1.5.0      PSWindowsUpdate                     PSGallery            15/01/2026 09:22:45
```

***

#### F. Mettre à Jour un Module

```powershell
Update-Module -Name AdminToolbox
```

**Explication :** Télécharge et installe la dernière version du module.

***

#### G. Désinstaller un Module

```powershell
Uninstall-Module -Name AdminToolbox
```

**Explication :** Supprime complètement le module du système.

***

### <mark style="color:blue;">7. Outils PowerShell Importants pour IT/Pentest</mark>

#### <mark style="color:green;">Tableau Récapitulatif</mark>

| Module              | Usage                                         | Type          |
| ------------------- | --------------------------------------------- | ------------- |
| **AdminToolbox**    | Administration système (AD, Exchange, Réseau) | Admin IT      |
| **ActiveDirectory** | Gestion complète Active Directory             | Admin IT      |
| **Empire/SA**       | Reconnaissance et énumération de domaine      | Pentest       |
| **Inveigh**         | Attaques Man-in-the-Middle, spoofing réseau   | Pentest       |
| **BloodHound**      | Cartographie visuelle d'Active Directory      | Pentest/Audit |
| **PowerSploit**     | Collection d'outils pour tests de pénétration | Pentest       |
| **PSWindowsUpdate** | Gestion des mises à jour Windows              | Admin IT      |

***

#### Descriptions Détaillées

**1. AdminToolbox**

```powershell
Find-Module AdminToolbox
Install-Module AdminToolbox -Scope CurrentUser
```

**Capacités :**

* Gestion Active Directory
* Administration Exchange
* Gestion réseau
* Problèmes de stockage

***

**2. ActiveDirectory Module**

```powershell
Import-Module ActiveDirectory
Get-Command -Module ActiveDirectory
```

**Exemples de commandes :**

* `Get-ADUser` : Obtenir des utilisateurs
* `New-ADUser` : Créer un utilisateur
* `Set-ADUser` : Modifier un utilisateur
* `Get-ADGroup` : Obtenir des groupes

***

**3. Empire (Situational Awareness)**

**Installation depuis GitHub nécessaire**

**Capacités :**

* Énumération de domaine
* Reconnaissance réseau
* Collecte d'informations sur les hôtes

***

**4. Inveigh**

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh
```

**Capacités :**

* Spoofing LLMNR/NBT-NS
* Attaques Man-in-the-Middle
* Capture de hashes

***

**5. BloodHound/SharpHound**

**Collecte de données AD :**

```powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

**Capacités :**

* Cartographie des relations AD
* Visualisation des chemins d'attaque
* Analyse de permissions

***

### <mark style="color:blue;">8. Récapitulatif des Commandes Principales</mark>

#### Gestion des Modules

```powershell
# Voir les modules chargés
Get-Module

# Voir tous les modules disponibles
Get-Module -ListAvailable

# Importer un module
Import-Module NomDuModule

# Voir les commandes d'un module
Get-Command -Module NomDuModule

# Supprimer un module de la session
Remove-Module NomDuModule
```

***

#### Execution Policy

```powershell
# Vérifier la politique
Get-ExecutionPolicy

# Voir toutes les portées
Get-ExecutionPolicy -List

# Changer pour la session actuelle (RECOMMANDÉ)
Set-ExecutionPolicy Bypass -Scope Process

# Changer globalement (nécessite admin)
Set-ExecutionPolicy RemoteSigned
```

***

```powershell
# Chercher un module
Find-Module -Name NomModule

# Installer un module
Install-Module -Name NomModule -Scope CurrentUser

# Voir les modules installés
Get-InstalledModule

# Mettre à jour un module
Update-Module -Name NomModule

# Désinstaller un module
Uninstall-Module -Name NomModule
```

***
