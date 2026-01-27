# Recherche et Filtrage dans PowerShell

## <mark style="color:red;">Recherche et Filtrage dans PowerShell</mark>

### <mark style="color:blue;">📚 Concepts Fondamentaux des Objets PowerShell</mark>

#### <mark style="color:green;">Qu'est-ce qu'un Objet ?</mark>

Un **objet** est une instance individuelle d'une classe dans PowerShell. Contrairement à Bash ou CMD qui manipulent du texte brut, PowerShell manipule des objets structurés.

**Analogie** : Un ordinateur est un objet. L'ensemble de ses composants (CPU, RAM, disque dur, etc.) le définit.

#### <mark style="color:green;">Composants d'un Objet</mark>

| Composant      | Définition                              | Exemple (Ordinateur)                       |
| -------------- | --------------------------------------- | ------------------------------------------ |
| **Classe**     | Le schéma ou "plan" qui définit l'objet | Le blueprint d'assemblage de l'ordinateur  |
| **Propriétés** | Les données associées à l'objet         | CPU, RAM, Disque dur, Carte graphique      |
| **Méthodes**   | Les fonctions que l'objet peut exécuter | Traiter des données, naviguer sur Internet |

***

### <mark style="color:blue;">🔍 Exploration des Objets et leurs Propriétés</mark>

#### <mark style="color:green;">Voir toutes les Propriétés et Méthodes d'un Objet</mark>

```powershell
Get-LocalUser administrator | Get-Member
```

**Sortie détaillée :**

```powershell
TypeName: Microsoft.PowerShell.Commands.LocalUser

Name                   MemberType Definition
----                   ---------- ----------
Clone                  Method     Microsoft.PowerShell.Commands.LocalUser Clone()
Equals                 Method     bool Equals(System.Object obj)
GetHashCode            Method     int GetHashCode()
GetType                Method     type GetType()
ToString               Method     string ToString()
AccountExpires         Property   System.Nullable[datetime] AccountExpires {get;set;}
Description            Property   string Description {get;set;}
Enabled                Property   bool Enabled {get;set;}
FullName               Property   string FullName {get;set;}
LastLogon              Property   System.Nullable[datetime] LastLogon {get;set;}
Name                   Property   string Name {get;set;}
ObjectClass            Property   string ObjectClass {get;set;}
PasswordChangeableDate Property   System.Nullable[datetime] PasswordChangeableDate {get;set;}
PasswordExpires        Property   System.Nullable[datetime] PasswordExpires {get;set;}
PasswordLastSet        Property   System.Nullable[datetime] PasswordLastSet {get;set;}
PasswordRequired       Property   bool PasswordRequired {get;set;}
PrincipalSource        Property   System.Nullable[Microsoft.PowerShell.Commands.PrincipalSource]
SID                    Property   System.Security.Principal.SecurityIdentifier SID {get;set;}
UserMayChangePassword  Property   bool UserMayChangePassword {get;set;}
```

**Explication :**

* **MemberType** : Indique si c'est une Method (action) ou Property (donnée)
* **Definition** : Montre le type de données et les actions possibles

***

#### <mark style="color:$success;">Afficher TOUTES les Propriétés d'un Objet</mark>

```powershell
Get-LocalUser administrator | Select-Object -Property *
```

**Sortie :**

```
AccountExpires         :
Description            : Built-in account for administering the computer/domain
Enabled                : False
FullName               :
PasswordChangeableDate :
PasswordExpires        :
UserMayChangePassword  : True
PasswordRequired       : True
PasswordLastSet        :
LastLogon              : 1/20/2021 5:39:14 PM
Name                   : Administrator
SID                    : S-1-5-21-3916821513-3027319641-390562114-500
PrincipalSource        : Local
ObjectClass            : User
```

***

### <mark style="color:blue;">🎯 Filtrage sur les Propriétés</mark>

#### <mark style="color:green;">Sélectionner des Propriétés Spécifiques</mark>

```powershell
Get-LocalUser * | Select-Object -Property Name,PasswordLastSet
```

**Sortie :**

```
Name               PasswordLastSet
----               ---------------
Administrator
DefaultAccount
Guest
MTanaka              1/27/2021 2:39:55 PM
WDAGUtilityAccount 1/18/2021 7:40:22 AM
```

**Explication :**

* `Get-LocalUser *` : Récupère TOUS les utilisateurs
* `Select-Object -Property Name,PasswordLastSet` : Affiche UNIQUEMENT ces 2 propriétés

***

#### <mark style="color:green;">Trier et Grouper les Objets</mark>

```powershell
Get-LocalUser * | Sort-Object -Property Name | Group-Object -Property Enabled
```

**Sortie :**

```
Count Name                      Group
----- ----                      -----
    4 False                     {Administrator, DefaultAccount, Guest, WDAGUtilityAccount}
    1 True                      {MTanaka}
```

**Explication détaillée :**

1. `Get-LocalUser *` : Récupère tous les utilisateurs
2. `Sort-Object -Property Name` : Les trie par ordre alphabétique
3. `Group-Object -Property Enabled` : Les groupe selon leur statut (Activé/Désactivé)
4. **Résultat** : 4 comptes désactivés, 1 compte activé (MTanaka)

***

### <mark style="color:blue;">🔎 Filtrage avec Where-Object</mark>

#### <mark style="color:green;">Opérateurs de Comparaison</mark>

| Opérateur   | Description                               | Exemple                                    |
| ----------- | ----------------------------------------- | ------------------------------------------ |
| `-like`     | Correspondance avec wildcards (\*)        | `'*Defender*'` trouve tout avec "Defender" |
| `-contains` | Correspondance exacte dans une collection | Vérifie si un élément existe               |
| `-eq`       | Égal à (case sensitive)                   | `$_.Status -eq 'Running'`                  |
| `-match`    | Expression régulière                      | Pattern matching avancé                    |
| `-not`      | Négation                                  | Propriété vide ou $False                   |
| `-gt`       | Supérieur à                               | `$_.CPU -gt 50`                            |
| `-lt`       | Inférieur à                               | `$_.Memory -lt 1000`                       |

***

#### <mark style="color:green;">Exemple Pratique : Recherche de Windows Defender</mark>

```powershell
Get-Service | Where-Object DisplayName -like '*Defender*'
```

**Sortie :**

```
Status   Name               DisplayName
------   ----               -----------
Running  mpssvc             Windows Defender Firewall
Stopped  Sense              Windows Defender Advanced Threat Pr...
Running  WdNisSvc           Microsoft Defender Antivirus Networ...
Running  WinDefend          Microsoft Defender Antivirus Service
```

**Explication :**

* `Get-Service` : Récupère TOUS les services
* `Where-Object DisplayName -like '*Defender*'` : Filtre pour garder uniquement ceux contenant "Defender"
* `*` : Wildcard = n'importe quels caractères avant et après "Defender"

***

#### <mark style="color:green;">Filtrage Avancé avec Propriétés Complètes</mark>

```powershell
Get-Service | Where-Object DisplayName -like '*Defender*' | Select-Object -Property *
```

**Sortie (exemple pour un service) :**

```
Name                : mpssvc
RequiredServices    : {mpsdrv, bfe}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
DisplayName         : Windows Defender Firewall
DependentServices   :
MachineName         : .
ServiceName         : mpssvc
ServicesDependedOn  : {mpsdrv, bfe}
ServiceHandle       :
Status              : Running
ServiceType         : Win32ShareProcess
StartType           : Automatic
Site                :
Container           :
```

**Analyse :**

* **Status** : Running = Le service est actif
* **StartType** : Automatic = Démarre automatiquement au boot
* **CanStop** : False = On ne peut pas l'arrêter avec nos permissions actuelles

***

### <mark style="color:blue;">⛓️ Le Pipeline PowerShell ( | )</mark>

#### <mark style="color:$success;">Concept</mark>

Le **Pipeline** permet de chaîner des commandes. La sortie d'une commande devient l'entrée de la suivante.

#### Syntaxes Valides

**Format 1 - Une seule ligne :**

```powershell
Command-1 | Command-2 | Command-3
```

**Format 2 - Multi-lignes :**

```powershell
Command-1 |
  Command-2 |
    Command-3
```

**Format 3 - Exemple réel :**

```powershell
Get-Process | Where-Object CPU | Where-Object Path | Get-Item
```

***

#### Exemple Pratique : Compter les Processus Uniques

```powershell
Get-Process | Sort-Object | Get-Unique | Measure-Object
```

**Sortie :**

```
Count             : 113
```

**Décomposition étape par étape :**

1. `Get-Process` → Récupère TOUS les processus
2. `Sort-Object` → Les trie par ordre alphabétique
3. `Get-Unique` → Supprime les doublons
4. `Measure-Object` → Compte le nombre total
5. **Résultat** : 113 processus uniques actifs

***

### <mark style="color:green;">🔗 Opérateurs de Chaîne ( && et || )</mark>

⚠️ **Important** : Nécessite PowerShell 7+, pas disponible dans Windows PowerShell 5.1

#### <mark style="color:$success;">Opérateur && (ET logique)</mark>

**Fonction** : Exécute la commande suivante SEULEMENT si la précédente réussit

```powershell
Get-Content '.\test.txt' && ping 8.8.8.8
```

**Sortie (Succès) :**

```
pass or fail

Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=23ms TTL=118
Reply from 8.8.8.8: bytes=32 time=28ms TTL=118
Reply from 8.8.8.8: bytes=32 time=28ms TTL=118
Reply from 8.8.8.8: bytes=32 time=21ms TTL=118

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 21ms, Maximum = 28ms, Average = 25ms
```

**Explication :**

* Le fichier existe → Get-Content réussit
* Comme la 1ère commande réussit → ping s'exécute

***

#### <mark style="color:green;">Opérateur || (OU logique)</mark>

**Fonction** : Exécute la commande suivante SEULEMENT si la précédente échoue

```powershell
Get-Content '.\test.txt' || ping 8.8.8.8
```

**Sortie (Fichier existe) :**

```
pass or fail
```

**Explication :**

* Le fichier existe → Get-Content réussit
* Comme la 1ère commande réussit → ping ne s'exécute PAS

***

**Sortie (Fichier n'existe pas) :**

```powershell
Get-Content '.\testss.txt' || ping 8.8.8.8
```

```
Get-Content: Cannot find path 'C:\Users\MTanaka\Desktop\testss.txt' because it does not exist.

Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=20ms TTL=118
Reply from 8.8.8.8: bytes=32 time=37ms TTL=118
Reply from 8.8.8.8: bytes=32 time=19ms TTL=118
```

**Explication :**

* Le fichier n'existe pas → Get-Content échoue
* Comme la 1ère commande échoue → ping s'exécute

***

### <mark style="color:blue;">🔍 Recherche dans le Contenu des Fichiers</mark>

#### <mark style="color:green;">Cmdlet Select-String (alias : sls)</mark>

**Équivalent de** : `grep` (Linux) ou `findstr.exe` (Windows CMD)

**Fonctionnalités :**

* Recherche par expressions régulières (regex)
* Affiche : ligne correspondante, nom du fichier, numéro de ligne
* Non sensible à la casse par défaut (utiliser `-CaseSensitive` si nécessaire)

***

#### <mark style="color:green;">Recherche Basique dans des Fichiers</mark>

{% code fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | Select-String "Password","credential","key"
```
{% endcode %}

**Sortie :**

```
CFP-Notes.txt:99:Lazzaro, N. (2004). Why we play games: Four keys to more emotion without story.
notes.txt:3:- Password: F@ll2022!
wmic.txt:67:  wmic netlogin get name,badpasswordcount
wmic.txt:69:Are the screensavers password protected? What is the timeout?
```

**Décomposition :**

* `Get-ChildItem -Path C:\Users\MTanaka\` : Cherche dans ce dossier
* `-Filter "*.txt"` : Uniquement les fichiers .txt
* `-Recurse` : Cherche aussi dans les sous-dossiers
* `-File` : Uniquement les fichiers (pas les dossiers)
* `Select-String "Password","credential","key"` : Cherche ces mots-clés

**Format de sortie :**

* `notes.txt:3:` = Fichier "notes.txt", ligne 3
* Ensuite le contenu de la ligne

***

#### <mark style="color:$success;">Recherche dans Plusieurs Types de Fichiers</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}
```
{% endcode %}

**Sortie :**

```
Directory: C:\Users\MTanaka\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/11/2022  3:32 PM            183 demo-notes.txt
-a---          10/11/2022 10:22 AM           1286 github-creds.txt
-a---            4/4/2022  9:37 AM            188 q2-to-do.txt
-a---           9/18/2022 12:35 PM             30 notes.txt
-a---          10/12/2022 11:26 AM             14 test.txt
-a---           2/14/2022  3:40 PM           3824 remote-connect.ps1
-a---          10/11/2022  8:22 PM            874 treats.ps1
-a---            1/4/2022 11:23 PM            310 Untitled-1.txt

Directory: C:\Users\MTanaka\Desktop\notedump\NoteDump

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           4/26/2022  1:47 PM           1092 demo.md
-a---           4/22/2022  2:20 PM           1074 noteDump.py
-a---           4/22/2022  2:20 PM            375 README.md
```

**Explication du filtre :**

* `$_.Name -like "*.txt"` : Fichiers .txt
* `-or` : OU logique
* Cherche : .txt, .py, .ps1, .md, .csv
* `-ErrorAction SilentlyContinue` : Ignore les erreurs (permissions refusées, etc.)

***

#### <mark style="color:green;">Recherche Combinée : Fichiers + Contenu</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")} | Select-String "Password","credential","key","UserName"
```
{% endcode %}

**Sortie :**

```
New-PC-Setup.md:56:  - getting your vpn key
CFP-Notes.txt:99:Lazzaro, N. (2004). Why we play games: Four keys to more emotion
notes.txt:3:- Password: F@ll2022!
wmic.txt:54:  wmic computersystem get username
wmic.txt:67:  wmic netlogin get name,badpasswordcount
wmic.txt:69:Are the screensavers password protected?
wmic.txt:83:  wmic netuse get Name,username,connectiontype,localname
```

**Processus complet :**

1. Trouve tous les fichiers (.txt, .py, .ps1, .md, .csv)
2. Dans tous les sous-dossiers (`-Recurse`)
3. Cherche dans leur contenu les mots : Password, credential, key, UserName
4. Affiche : nom du fichier, ligne, contenu

**💎 Découverte :** Le fichier `notes.txt` ligne 3 contient un mot de passe !

***

### <mark style="color:blue;">📂 Emplacements Importants à Vérifier</mark>

#### Dossiers Sensibles pour l'Énumération

| Emplacement                | Description                                  | Commande Utile                                                                                    |
| -------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `C:\Users\<USER>\AppData\` | Configs d'applications, fichiers temporaires | `Get-ChildItem -Hidden -Recurse`                                                                  |
| `C:\Users\<USER>\`         | Dossier utilisateur (clés VPN, SSH)          | `Get-ChildItem -Hidden`                                                                           |
| Historique PowerShell      | Toutes les commandes exécutées               | `Get-Content (Get-PSReadlineOption).HistorySavePath`                                              |
| Historique alternatif      | Ancien format d'historique                   | `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| Presse-papiers             | Contenu copié actuellement                   | `Get-Clipboard`                                                                                   |
| Tâches planifiées          | Scripts automatisés                          | `Get-ScheduledTask`                                                                               |

***

#### <mark style="color:green;">Exemples de Commandes d'Énumération</mark>

**Chercher des fichiers cachés :**

```powershell
Get-ChildItem -Path C:\Users\MTanaka\ -Hidden -Recurse
```

**Lire l'historique PowerShell :**

```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

**Voir le presse-papiers :**

```powershell
Get-Clipboard
```

***

### 🎓 Scénario Complet de Pentest

#### Objectif : Trouver des Credentials

**Étape 1 - Chercher des fichiers intéressants :**

{% code overflow="wrap" fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Name -like "*.txt" -or $_.Name -like "*.ps1" -or $_.Name -like "*.xml" -or $_.Name -like "*.ini")}
```
{% endcode %}

**Étape 2 - Chercher des mots-clés sensibles :**

{% code overflow="wrap" fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object {($_.Name -like "*.txt" -or $_.Name -like "*.ps1")} | Select-String "password","pwd","pass","credential","key","token","secret"
```
{% endcode %}

**Étape 3 - Vérifier l'historique :**

{% code fullWidth="true" %}
```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath | Select-String "password","credential"
```
{% endcode %}

**Étape 4 - Chercher les clés SSH/VPN :**

{% code fullWidth="true" %}
```powershell
Get-ChildItem -Path C:\Users\ -Filter "*.key" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Filter "*.pem" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Filter "*.ovpn" -Recurse -ErrorAction SilentlyContinue
```
{% endcode %}

***

### <mark style="color:blue;">📊 Tableau Récapitulatif des Cmdlets Clés</mark>

| Cmdlet           | Alias        | Usage Principal          | Exemple                |
| ---------------- | ------------ | ------------------------ | ---------------------- |
| `Get-Member`     | `gm`         | Voir propriétés/méthodes | \`Get-Process          |
| `Select-Object`  | `select`     | Choisir des propriétés   | \`Get-Process          |
| `Where-Object`   | `where`, `?` | Filtrer les objets       | \`Get-Service          |
| `Sort-Object`    | `sort`       | Trier les résultats      | \`Get-Process          |
| `Group-Object`   | `group`      | Grouper par propriété    | \`Get-Service          |
| `Measure-Object` | `measure`    | Compter, calculer        | \`Get-Process          |
| `Select-String`  | `sls`        | Chercher dans le contenu | \`Get-Content file.txt |
| `Get-Unique`     | -            | Supprimer les doublons   | \`Get-Process          |

***

### <mark style="color:blue;">💡 Tips et Astuces Avancées</mark>

#### Rendre les Commandes Plus Lisibles

**Utiliser le backtick (\`) pour les sauts de ligne :**

```powershell
Get-ChildItem -Path C:\Users\MTanaka\ `
  -File `
  -Recurse `
  -ErrorAction SilentlyContinue | `
  Where-Object {$_.Name -like "*.txt"} | `
  Select-String "password"
```

#### Optimisation des Performances

* Utiliser `-ErrorAction SilentlyContinue` pour éviter les blocages
* Limiter la profondeur de recherche si possible
* Utiliser des filtres précis plutôt que de tout récupérer puis filtrer

#### Variables pour Réutilisation

```powershell
$files = Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse
$files | Where-Object {$_.Name -like "*.txt"}
$files | Select-String "password"
```
