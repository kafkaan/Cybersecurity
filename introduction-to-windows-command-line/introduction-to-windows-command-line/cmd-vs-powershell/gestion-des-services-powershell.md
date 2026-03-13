# Gestion des Services PowerShell

## <mark style="color:red;">Gestion des Services PowerShell</mark>

### <mark style="color:blue;">📋 Vue d'ensemble</mark>

Les services Windows sont des composants qui s'exécutent en arrière-plan pour gérer et maintenir les processus nécessaires aux applications. Ils ne nécessitent généralement pas d'interaction utilisateur et n'ont pas d'interface visible.

#### <mark style="color:green;">Types de services Windows</mark>

* **Local Services** - Services locaux
* **Network Services** - Services réseau
* **System Services** - Services système

#### <mark style="color:green;">États possibles</mark>

* **Running** - En cours d'exécution
* **Stopped** - Arrêté
* **Paused** - En pause

#### <mark style="color:green;">Modes de démarrage</mark>

* **Manual** - Démarrage manuel (interaction utilisateur)
* **Automatic** - Démarrage automatique (au démarrage système)
* **Delayed** - Démarrage différé (après le boot)
* **Disabled** - Désactivé

***

### <mark style="color:blue;">🔍 Commandes de Base</mark>

#### <mark style="color:green;">1. Obtenir l'aide sur les cmdlets de services</mark>

```powershell
Get-Help *-Service
```

**Sortie :**

```
Name                  Category  Module                       Synopsis
----                  --------  ------                       --------
Get-Service           Cmdlet    Microsoft.PowerShell.Man…    …
New-Service           Cmdlet    Microsoft.PowerShell.Man…    …
Remove-Service        Cmdlet    Microsoft.PowerShell.Man…    …
Restart-Service       Cmdlet    Microsoft.PowerShell.Man…    …
Resume-Service        Cmdlet    Microsoft.PowerShell.Man…    …
Set-Service           Cmdlet    Microsoft.PowerShell.Man…    …
Start-Service         Cmdlet    Microsoft.PowerShell.Man…    …
Stop-Service          Cmdlet    Microsoft.PowerShell.Man…    …
Suspend-Service       Cmdlet    Microsoft.PowerShell.Man…    …
```

***

### <mark style="color:blue;">📊 Lister les Services</mark>

#### <mark style="color:green;">2. Lister tous les services avec nom d'affichage et état</mark>

```powershell
Get-Service | ft DisplayName,Status
```

**Sortie :**

```
DisplayName                                              Status
-----------                                              ------
Adobe Acrobat Update Service                             Running
OpenVPN Agent agent_ovpnconnect                          Running
Adobe Genuine Monitor Service                            Running
Application Layer Gateway Service                        Stopped
Application Identity                                     Stopped
Application Information                                  Running
Windows Audio Endpoint Builder                           Running
Windows Audio                                            Running
BitLocker Drive Encryption Service                       Running
Base Filtering Engine                                    Running
```

**Détails :**

* `Get-Service` : Récupère tous les services
* `|` : Pipeline pour passer les résultats
* `ft` : Alias de `Format-Table`
* `DisplayName,Status` : Propriétés à afficher

***

#### <mark style="color:blue;">3. Compter le nombre total de services</mark>

```powershell
Get-Service | measure
```

**Sortie :**

```
Count
-----
  321
```

**Détails :**

* `measure` : Alias de `Measure-Object`
* Compte le nombre d'objets dans le pipeline

***

### <mark style="color:blue;">🔎 Filtrer les Services</mark>

#### <mark style="color:green;">4. Rechercher des services spécifiques (Defender)</mark>

```powershell
Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status
```

**Sortie :**

```
DisplayName                                             ServiceName  Status
-----------                                             -----------  ------
Windows Defender Firewall                               mpssvc       Running
Windows Defender Advanced Threat Protection Service     Sense        Stopped
Microsoft Defender Antivirus Network Inspection Service WdNisSvc     Running
Microsoft Defender Antivirus Service                    WinDefend    Stopped
```

**Détails :**

* `where` : Alias de `Where-Object`
* `DisplayName -like '*Defender*'` : Filtre les services contenant "Defender"
* `*` : Caractère joker (wildcard)

***

### <mark style="color:blue;">▶️ Démarrer un Service</mark>

#### <mark style="color:$success;">5. Démarrer un service arrêté</mark>

```powershell
Start-Service WinDefend
```

**Sortie :** Aucune sortie si succès (commande silencieuse)

**Erreurs possibles :**

* "ParserError: This script contains malicious content..."
* Erreur de permissions

***

#### <mark style="color:$success;">6. Vérifier qu'un service est démarré</mark>

```powershell
Get-Service WinDefend
```

**Sortie :**

```
Status   Name               DisplayName
------   ----               -----------
Running  WinDefend          Microsoft Defender Antivirus Service
```

**Détails :**

* Interroge un service spécifique par son nom
* Plus rapide que de lister tous les services

***

### <mark style="color:blue;">⏹️ Arrêter un Service</mark>

#### <mark style="color:$success;">7. Arrêter un service en cours d'exécution</mark>

```powershell
Stop-Service Spooler
```

**Sortie :** Aucune sortie si succès

***

#### <mark style="color:green;">8. Vérifier l'arrêt du service</mark>

```powershell
Get-Service Spooler
```

**Sortie :**

```
Status   Name               DisplayName
------   ----               -----------
Stopped  spooler            Totally still used for Print Spooli...
```

***

### <mark style="color:blue;">⚙️ Modifier la Configuration d'un Service</mark>

#### <mark style="color:green;">9. Afficher les propriétés détaillées d'un service</mark>

```powershell
Get-Service spooler | Select-Object -Property Name, StartType, Status, DisplayName
```

**Sortie :**

```
Name    StartType  Status  DisplayName
----    ---------  ------  -----------
spooler Automatic  Stopped Totally still used for Print Spooling...
```

**Détails :**

* `Select-Object` : Sélectionne des propriétés spécifiques
* `-Property` : Paramètre pour lister les propriétés voulues

***

#### <mark style="color:green;">10. Modifier le type de démarrage d'un service</mark>

```powershell
Set-Service -Name Spooler -StartType Disabled
```

**Sortie :** Aucune sortie si succès

***

#### <mark style="color:green;">11. Vérifier la modification</mark>

```powershell
Get-Service -Name Spooler | Select-Object -Property StartType
```

**Sortie :**

```
StartType
---------
Disabled
```

**Options de StartType :**

* `Automatic` - Démarrage automatique
* `Manual` - Démarrage manuel
* `Disabled` - Désactivé
* `AutomaticDelayedStart` - Démarrage automatique différé

***

### <mark style="color:blue;">🌐 Gestion des Services à Distance</mark>

#### <mark style="color:green;">12. Interroger les services d'un hôte distant</mark>

```powershell
Get-Service -ComputerName ACADEMY-ICL-DC
```

**Sortie :**

```
Status   Name               DisplayName
------   ----               -----------
Running  ADWS               Active Directory Web Services
Stopped  AppIDSvc           Application Identity
Stopped  AppMgmt            Application Management
Stopped  AppReadiness       App Readiness
Stopped  AppXSvc            AppX Deployment Service (AppXSVC)
Running  BFE                Base Filtering Engine
Stopped  BITS               Background Intelligent Transfer Ser...
```

**Détails :**

* `-ComputerName` : Spécifie l'hôte distant à interroger
* Nécessite des permissions appropriées

***

#### <mark style="color:green;">13. Filtrer les services distants par état</mark>

```powershell
Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}
```

**Sortie :**

```
Status   Name               DisplayName
------   ----               -----------
Running  ADWS               Active Directory Web Services
Running  BFE                Base Filtering Engine
Running  COMSysApp          COM+ System Application
Running  CoreMessagingRe... CoreMessaging
Running  CryptSvc           Cryptographic Services
Running  DcomLaunch         DCOM Server Process Launcher
Running  Dfs                DFS Namespace
Running  DFSR               DFS Replication
```

**Détails :**

* `{$_.Status -eq "Running"}` : Bloc de script pour filtrer
* `$_` : Représente l'objet actuel dans le pipeline
* `-eq` : Opérateur d'égalité

***

#### <mark style="color:green;">14. Interroger plusieurs hôtes simultanément avec Invoke-Command</mark>

{% code fullWidth="true" %}
```powershell
Invoke-Command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}
```
{% endcode %}

**Sortie :**

```
Status   Name        DisplayName                            PSComputerName
------   ----        -----------                            --------------
Running  windefend   Microsoft Defender Antivirus Service   LOCALHOST
Running  windefend   Windows Defender Antivirus Service     ACADEMY-ICL-DC
```

**Détails de la commande :**

* `Invoke-Command` : Exécute une commande sur des ordinateurs locaux ou distants
* `-ComputerName ACADEMY-ICL-DC,LOCALHOST` : Liste des ordinateurs séparés par des virgules
* `-ScriptBlock {commandes}` : Bloc de commandes à exécuter (doit être entre accolades)
* `PSComputerName` : Propriété ajoutée automatiquement indiquant l'hôte source

***

### <mark style="color:blue;">🔄 Autres Commandes Utiles</mark>

#### <mark style="color:green;">15. Redémarrer un service</mark>

```powershell
Restart-Service -Name WinDefend
```

**Usage :** Arrête puis redémarre le service en une seule commande

***

#### <mark style="color:green;">16. Mettre en pause un service</mark>

```powershell
Suspend-Service -Name ServiceName
```

**Usage :** Met le service en pause (si le service le supporte)

***

#### <mark style="color:green;">17. Reprendre un service en pause</mark>

```powershell
Resume-Service -Name ServiceName
```

**Usage :** Reprend l'exécution d'un service en pause

***

### <mark style="color:blue;">📝 Notes Importantes</mark>

#### <mark style="color:green;">Permissions requises</mark>

* **Lecture** : Aucune permission spéciale nécessaire
* **Modification** : Droits d'administrateur local ou permissions du domaine
* **Astuce** : Ouvrir PowerShell en tant qu'administrateur (clic droit → "Exécuter en tant qu'administrateur")

#### <mark style="color:green;">Suppression de services</mark>

* `Remove-Service` : Disponible uniquement dans **PowerShell 7+**
* PowerShell par défaut : **Version 5.1**
* Alternative : Utiliser `sc.exe delete NomDuService`

#### <mark style="color:green;">Propriétés importantes</mark>

* **Name** : Nom du service (utilisé dans les commandes)
* **DisplayName** : Nom d'affichage (visible pour l'utilisateur)
* **Status** : État actuel (Running, Stopped, Paused)
* **StartType** : Mode de démarrage

***

### <mark style="color:blue;">🎯 Cas d'Usage Pratiques</mark>

#### Rechercher un service modifié sur plusieurs hôtes

```powershell
Invoke-Command -ComputerName PC01,PC02,PC03 -ScriptBlock {
    Get-Service | Where-Object {$_.DisplayName -like '*modifié*'}
}
```

#### Démarrer tous les services Windows Defender

```powershell
Get-Service | Where-Object {$_.DisplayName -like '*Defender*' -and $_.Status -eq 'Stopped'} | Start-Service
```

#### Créer un rapport de services sur plusieurs serveurs

```powershell
$servers = "SRV01","SRV02","SRV03"
Invoke-Command -ComputerName $servers -ScriptBlock {
    Get-Service | Where-Object {$_.Status -eq 'Running'}
} | Select-Object PSComputerName, Name, DisplayName, Status | Export-Csv -Path "C:\rapport_services.csv"
```

***

<table data-full-width="true"><thead><tr><th width="75">#</th><th width="800">Commande</th><th>Description</th></tr></thead><tbody><tr><td>1</td><td><code>Get-Help *-Service</code></td><td>Liste toutes les cmdlets liées aux services</td></tr><tr><td>2</td><td><code>Get-Service | ft DisplayName,Status</code></td><td>Liste tous les services avec nom et état</td></tr><tr><td>3</td><td><code>Get-Service | measure</code></td><td>Compte le nombre total de services</td></tr><tr><td>4</td><td><code>Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status</code></td><td>Recherche les services contenant "Defender"</td></tr><tr><td>5</td><td><code>Start-Service WinDefend</code></td><td>Démarre un service arrêté</td></tr><tr><td>6</td><td><code>Get-Service WinDefend</code></td><td>Vérifie l'état d'un service</td></tr><tr><td>7</td><td><code>Stop-Service Spooler</code></td><td>Arrête un service</td></tr><tr><td>8</td><td><code>Get-Service spooler | Select-Object -Property Name, StartType, Status, DisplayName</code></td><td>Affiche les propriétés détaillées d'un service</td></tr><tr><td>9</td><td><code>Set-Service -Name Spooler -StartType Disabled</code></td><td>Modifie le type de démarrage</td></tr><tr><td>10</td><td><code>Get-Service -Name Spooler | Select-Object -Property StartType</code></td><td>Vérifie le type de démarrage</td></tr><tr><td>11</td><td><code>Get-Service -ComputerName ACADEMY-ICL-DC</code></td><td>Liste les services d'un hôte distant</td></tr><tr><td>12</td><td><code>Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}</code></td><td>Filtre les services distants par état</td></tr><tr><td>13</td><td><code>Invoke-Command -ComputerName PC1,PC2 -ScriptBlock {Get-Service -Name 'windefend'}</code></td><td>Interroge plusieurs hôtes en même temps</td></tr><tr><td>14</td><td><code>Restart-Service -Name WinDefend</code></td><td>Redémarre un service</td></tr><tr><td>15</td><td><code>Suspend-Service -Name ServiceName</code></td><td>Met un service en pause</td></tr><tr><td>16</td><td><code>Resume-Service -Name ServiceName</code></td><td>Reprend un service en pause</td></tr></tbody></table>
