# Script PowerShell et Automatisation

## <mark style="color:red;">Script PowerShell et Automatisation</mark>

### <mark style="color:blue;">Comprendre le Script PowerShell</mark>

PowerShell, par sa nature, est modulaire et permet un contrôle significatif de son utilisation.&#x20;

La pensée traditionnelle lorsqu'on traite de scripts est que nous écrivons une forme d'exécutable qui effectue des tâches pour nous dans le langage dans lequel il a été créé. Avec PowerShell, cela reste vrai, à l'exception qu'il peut gérer des entrées de plusieurs langages et types de fichiers différents et peut gérer de nombreux types d'objets différents. Nous pouvons utiliser des scripts singuliers de la manière habituelle en les appelant en utilisant la syntaxe `.\script` et en important des modules en utilisant la cmdlet `Import-Module`. Maintenant, parlons un peu des scripts et des modules.

***

### <mark style="color:blue;">Scripts vs. Modules</mark>

La façon la plus simple de penser est qu'un script est un fichier texte exécutable contenant des cmdlets et des fonctions PowerShell, tandis qu'un module peut être juste un simple script, ou une collection de plusieurs fichiers de script, manifestes et fonctions regroupés ensemble.&#x20;

L'autre différence principale réside dans leur utilisation. Vous appelleriez généralement un script en l'exécutant directement, tandis que vous pouvez importer un module et tous les scripts et fonctions associés à appeler à votre guise. Pour cette section, nous en discuterons en utilisant le même terme, et tout ce dont nous parlons dans un fichier de module fonctionne dans un script PowerShell standard. Tout d'abord, les extensions de fichiers et ce qu'elles signifient pour nous.

***

### <mark style="color:blue;">Extensions de Fichiers</mark>

#### <mark style="color:green;">Extensions PowerShell</mark>

<table data-full-width="true"><thead><tr><th>Extension</th><th>Description</th></tr></thead><tbody><tr><td>ps1</td><td>L'extension de fichier *.ps1 représente des scripts PowerShell exécutables.</td></tr><tr><td>psm1</td><td>L'extension de fichier *.psm1 représente un fichier de module PowerShell. Il définit ce qu'est le module et ce qu'il contient.</td></tr><tr><td>psd1</td><td>Le *.psd1 est un fichier de données PowerShell détaillant le contenu d'un module PowerShell dans une table de paires clé/valeur.</td></tr></tbody></table>

***

### <mark style="color:blue;">Créer un Module</mark>

**Scénario :** Nous nous sommes retrouvés à effectuer les mêmes vérifications encore et encore lors de l'administration des hôtes. Donc, pour accélérer nos tâches, nous allons créer un module PowerShell pour exécuter les vérifications pour nous et ensuite sortir les informations que nous demandons. Notre module, lorsqu'il est utilisé, devrait sortir le nom d'ordinateur de l'hôte, l'adresse IP et les informations de domaine de base, et nous fournir la sortie du répertoire `C:\Users\` afin que nous puissions voir quels utilisateurs se sont connectés de manière interactive à cet hôte.

***

### <mark style="color:blue;">Composants du Module</mark>

Un module est composé de quatre composants essentiels :

1.  **Un répertoire** contenant tous les fichiers et contenus requis, enregistré quelque part dans `$env:PSModulePath`.

    Cela est fait de sorte que lorsque vous tentez de l'importer dans votre session PowerShell ou Profil, il peut être automatiquement trouvé au lieu d'avoir à spécifier où il se trouve.
2.  **Un fichier manifeste** listant tous les fichiers et informations pertinentes sur le module et sa fonction.

    Cela pourrait inclure des scripts associés, des dépendances, l'auteur, un exemple d'utilisation, etc.
3. **Un fichier de code** - généralement soit un script PowerShell (.ps1) ou un fichier de module (.psm1) qui contient nos fonctions de script et d'autres informations.
4. **D'autres ressources** dont le module a besoin, telles que des fichiers d'aide, des scripts et d'autres documents de support.

***

### <mark style="color:blue;">Créer un Répertoire pour Contenir Notre Module</mark>

Créer un répertoire est super simple, comme discuté dans les sections précédentes. Avant d'aller plus loin, nous devons créer le répertoire pour contenir notre module. Ce répertoire devrait être dans l'un des chemins dans `$env:PSModulePath`. Si vous n'êtes pas sûr de ce que sont ces chemins, vous pouvez appeler la variable pour voir où serait le meilleur endroit. Nous allons donc créer un dossier nommé `quick-recon`.

#### Mkdir

```powershell
PS C:\htb> mkdir quick-recon  

    Directory: C:\Users\MTanaka\Documents\WindowsPowerShell\Modules


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/31/2022   7:38 AM                quick-recon
```

Maintenant que nous avons notre répertoire, nous pouvons créer le module. Discutons d'un fichier manifeste de module pendant une seconde.

***

### Manifeste du Module

Un manifeste de module est un simple fichier .psd1 qui contient une table de hachage. Les clés et valeurs dans la table de hachage effectuent les fonctions suivantes :

* Décrire le contenu et les attributs du module.
* Définir les prérequis (modules spécifiques externes au module lui-même, variables, fonctions, etc.)
* Déterminer comment les composants sont traités.

Si vous ajoutez un fichier manifeste au dossier du module, vous pouvez référencer plusieurs fichiers comme une seule unité en référençant le manifeste. Le manifeste décrit les informations suivantes :

* Métadonnées sur le module, telles que le numéro de version du module, l'auteur et la description.
* Prérequis nécessaires pour importer le module, tels que la version de Windows PowerShell, la version du common language runtime (CLR) et les modules requis.
* Directives de traitement, telles que les scripts, formats et types à traiter.
* Restrictions sur les membres du module à exporter, telles que les alias, fonctions, variables et cmdlets à exporter.

Nous pouvons rapidement créer un fichier manifeste en utilisant `New-ModuleManifest` et en spécifiant où nous voulons qu'il soit placé.

#### <mark style="color:green;">New-ModuleManifest</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> New-ModuleManifest -Path C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon\quick-recon.psd1 -PassThru

# Module manifest for module 'quick-recon'
#
# Generated by: MTanaka
#
# Generated on: 10/31/2022
#

@{

# Script module or binary module file associated with this manifest.
# RootModule = ''

# Version number of this module.
ModuleVersion = '1.0'

<SNIP>
```
{% endcode %}

En émettant la commande ci-dessus, nous avons provisionné un nouveau fichier manifeste rempli avec les considérations par défaut. Le modificateur `-PassThru` nous permet de voir ce qui est imprimé dans le fichier et sur la console.&#x20;

Nous pouvons maintenant entrer et remplir les sections que nous voulons avec les informations pertinentes. Rappelez-vous que toutes les lignes dans les fichiers manifestes sont optionnelles sauf la ligne `ModuleVersion`.

#### Exemple de Manifeste

{% code fullWidth="true" %}
```powershell
# Module manifest for module 'quick-recon'
#
# Generated by: MTanaka
#
# Generated on: 10/31/2022
#

@{

# Script module or binary module file associated with this manifest.
# RootModule = 'C:\Users\MTanaka\WindowsPowerShell\Modules\quick-recon\quick-recon.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '0a062bb1-8a1b-4bdb-86ed-5adbe1071d2f'

# Author of this module
Author = 'MTanaka'

# Company or vendor of this module
CompanyName = 'Greenhorn.Corp.'

# Copyright statement for this module
Copyright = '(c) 2022 Greenhorn.Corp. All rights reserved.'

# Description of the functionality provided by this module
Description = 'This module will perform several quick checks against the host for Reconnaissance of key information.'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()  
}
```
{% endcode %}

***

### <mark style="color:blue;">Créer Notre Fichier de Script</mark>

Nous pouvons utiliser la cmdlet `New-Item` (ni) pour créer notre fichier.

#### New-Item

```powershell
PS C:\htb>  ni quick-recon.psm1 -ItemType File


    Directory: C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/31/2022   9:07 AM              0 quick-recon.psm1
```

***

### <mark style="color:blue;">Importer les Modules Dont Vous Avez Besoin</mark>

#### Import Dans Notre Module

```powershell
Import-Module ActiveDirectory 
```

***

### <mark style="color:blue;">Fonctions et Travail avec PowerShell</mark>

Nous devons faire quatre choses principales avec ce module :

1. Récupérer le ComputerName de l'hôte
2. Récupérer la configuration IP de l'hôte
3. Récupérer les informations de domaine de base
4. Récupérer une sortie du répertoire "C:\Users"

Pour commencer, concentrons-nous sur la sortie du ComputerName.&#x20;

Nous pouvons obtenir cela de plusieurs façons avec diverses cmdlets, modules et commandes DOS.&#x20;

Notre script utilisera la variable d'environnement (`$env:ComputerName`) pour acquérir le nom d'hôte pour la sortie.&#x20;

Pour rendre notre sortie plus facile à lire plus tard, nous utiliserons une autre variable nommée `$hostname` pour stocker la sortie de la variable d'environnement. Pour capturer l'adresse IP pour les adaptateurs hôtes actifs, nous utiliserons IPConfig et stockerons cette information dans la variable `$IP`. Pour les informations de domaine de base, nous utiliserons `Get-ADDomain` et stockerons la sortie dans `$Domain`. Enfin, nous obtiendrons une liste des dossiers utilisateurs dans `C:\Users\` avec `Get-ChildItem` et la stockerons dans `$Users`. Pour créer nos variables, nous devons d'abord spécifier un nom comme (`$Hostname`), ajouter le symbole "=", puis le suivre avec l'action ou les valeurs que nous voulons qu'il contienne. Par exemple, la première variable dont nous avons besoin, `$Hostname`, apparaîtrait comme ceci : (`$Hostname = $env:ComputerName`). Maintenant plongeons et créons le reste de nos variables pour utilisation.

#### Variables

```powershell
Import-Module ActiveDirectory 

$Hostname = $env:ComputerName
$IP = ipconfig 
$Domain = Get-ADDomain  
$Users = Get-ChildItem C:\Users\ 
```

Nos variables sont maintenant configurées pour exécuter des commandes ou fonctions singulières, récupérant la sortie nécessaire. Maintenant formatons ces données et donnons-nous une belle sortie. Nous pouvons le faire en écrivant le résultat dans un fichier en utilisant `New-Item` et `Add-Content`. Pour faciliter les choses, nous ferons de ce processus de sortie une fonction appelable appelée `Get-Recon`.

#### Sortir Nos Informations

```powershell
Import-Module ActiveDirectory

function Get-Recon {  

    $Hostname = $env:ComputerName  

    $IP = ipconfig

    $Domain = Get-ADDomain 

    $Users = Get-ChildItem C:\Users\

    new-Item ~\Desktop\recon.txt -ItemType File 

    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users

    Add-Content ~\Desktop\recon.txt $Vars
  } 
```

### <mark style="color:blue;">Commentaires dans le Script</mark>

Le (#) dira à PowerShell que la ligne contient un commentaire dans votre script ou fichier de module. Si vos commentaires vont englober plusieurs lignes, vous pouvez utiliser le `<#` et `#>` pour envelopper plusieurs lignes comme un grand commentaire comme vu ci-dessous :

#### Blocs de Commentaires

```powershell
# Ceci est un commentaire sur une seule ligne.  

<# Cette ligne et les lignes suivantes sont toutes enveloppées dans le spécificateur de Commentaire. 
Rien dans cette fenêtre ne sera prêt par le script en tant que partie d'une fonction.
Ce texte existe purement pour le créateur et nous pour transmettre des informations pertinentes.

#>  
```

#### Commentaires Ajoutés

```powershell
Import-Module ActiveDirectory

function Get-Recon {  
    # Collecter le nom d'hôte de notre PC.
    $Hostname = $env:ComputerName  
    # Collecter la configuration IP.
    $IP = ipconfig
    # Collecter les informations de domaine de base.
    $Domain = Get-ADDomain 
    # Sortir les utilisateurs qui se sont connectés et ont construit une structure de répertoire de base dans "C:\Users\".
    $Users = Get-ChildItem C:\Users\
    # Créer un nouveau fichier pour placer nos résultats de reconnaissance.
    new-Item ~\Desktop\recon.txt -ItemType File 
    # Une variable pour contenir les résultats de nos autres variables. 
    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
    # Ça fait le truc 
    Add-Content ~\Desktop\recon.txt $Vars
  } 
```

***

### <mark style="color:blue;">Inclure l'Aide</mark>

PowerShell utilise une forme d'aide basée sur les commentaires pour intégrer tout ce dont vous avez besoin pour le script ou le module. Nous pouvons utiliser des blocs de commentaires comme ceux dont nous avons discuté ci-dessus, ainsi que des mots-clés reconnus pour construire la section d'aide et même l'appeler en utilisant `Get-Help` par la suite. En ce qui concerne le placement, nous avons deux options ici. Nous pouvons placer l'aide dans la fonction elle-même ou à l'extérieur de la fonction dans le script.&#x20;

Si nous souhaitons la placer dans la fonction, elle doit être au début de la fonction, juste après la ligne d'ouverture pour la fonction, ou à la fin de la fonction, une ligne après la dernière action de la fonction. Si nous la plaçons dans le script mais à l'extérieur de la fonction elle-même, nous devons la placer au-dessus de notre fonction avec pas plus d'une ligne entre l'aide et la fonction. Pour une plongée plus profonde dans l'aide dans PowerShell, consultez cet article. Maintenant définissons notre section d'aide. Nous la placerons à l'extérieur de la fonction en haut du script pour l'instant.

#### Aide du Module

```powershell
Import-Module ActiveDirectory

<# 
.Description  
Cette fonction effectue quelques tâches de reconnaissance simples pour l'utilisateur. Nous importons le module et émettons la commande 'Get-Recon' pour récupérer notre sortie. Chaque variable et ligne dans la fonction et le script sont commentées pour notre compréhension. Pour l'instant, ce module ne fonctionnera que sur l'hôte local à partir duquel vous l'exécutez, et la sortie sera envoyée à un fichier nommé 'recon.txt' sur le Bureau de l'utilisateur qui a ouvert le shell. Les fonctions de Recon à distance arrivent bientôt !  

.Example  
Après avoir importé le module, exécutez "Get-Recon"
'Get-Recon


    Directory: C:\Users\MTanaka\Desktop


Mode                 LastWriteTime         Length Name                                                                                                                                        
----                 -------------         ------ ----                                                                                                                                        
-a----         11/3/2022  12:46 PM              0 recon.txt '

.Notes  
Les fonctions de Recon à distance arrivent bientôt ! Ce script sert de notre introduction initiale à l'écriture de fonctions et scripts et à la création de modules PowerShell.  

#>

function Get-Recon {  
<SNIP>  
```

***

### <mark style="color:blue;">Protéger les Fonctions</mark>

Nous pouvons ajouter des fonctions à nos scripts que nous ne voulons pas être accessibles, exportées ou utilisées par d'autres scripts ou processus dans PowerShell. Pour protéger une fonction d'être exportée ou pour la définir explicitement pour l'exportation, `Export-ModuleMember` est la cmdlet pour le travail. Le contenu est exportable si nous laissons cela hors de nos modules de script. Si nous le plaçons dans le fichier mais le laissons vide comme ceci :

#### Exclure de l'Exportation

```powershell
Export-ModuleMember  
```

Cela garantit que les variables, alias et fonctions du module ne peuvent pas être exportés. Si nous souhaitons spécifier quoi exporter, nous pouvons les ajouter à la chaîne de commande comme ceci :

#### Exporter des Fonctions et Variables Spécifiques

```powershell
Export-ModuleMember -Function Get-Recon -Variable Hostname 
```

Alternativement, si vous vouliez seulement exporter toutes les fonctions et une variable spécifique, par exemple, vous pourriez émettre le \* après `-Function` puis spécifier les Variables à exporter explicitement. Alors ajoutons la cmdlet `Export-ModuleMember` à notre script et spécifions que nous voulons autoriser notre fonction `Get-Recon` et notre variable `Hostname` à être disponibles pour l'exportation.

#### Ajout de Ligne d'Exportation

```powershell
<SNIP>  
function Get-Recon {  
    # Collecter le nom d'hôte de notre PC
    $Hostname = $env:ComputerName  
    # Collecter la configuration IP
    $IP = ipconfig
    # Collecter les informations de domaine de base
    $Domain = Get-ADDomain 
    # Sortir les utilisateurs qui se sont connectés et ont construit une structure de répertoire de base dans "C:\Users"
    $Users = Get-ChildItem C:\Users\
    # Créer un nouveau fichier pour placer nos résultats de reconnaissance
    new-Item ~\Desktop\recon.txt -ItemType File 
    # Une variable pour contenir les résultats de nos autres variables 
    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
    # Ça fait le truc 
    Add-Content ~\Desktop\recon.txt $Vars
  } 

Export-ModuleMember -Function Get-Recon -Variable Hostname  
```

***

### <mark style="color:blue;">Portée</mark>

Lorsqu'on traite avec des scripts, la session PowerShell et comment les choses sont reconnues à la ligne de commande, le concept de Portée entre en jeu. La portée, en essence, est comment PowerShell reconnaît et protège les objets dans la session contre l'accès ou la modification non autorisés. PowerShell utilise actuellement trois niveaux de Portée différents :

#### Niveaux de Portée

| Portée | Description                                                                                                                                                                                                                                                                                              |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Global | C'est le niveau de portée par défaut pour PowerShell. Il affecte tous les objets qui existent lorsque PowerShell démarre, ou qu'une nouvelle session est ouverte. Toutes les variables, alias, fonctions et tout ce que vous spécifiez dans votre profil PowerShell seront créés dans la portée Globale. |
| Local  | C'est la portée actuelle dans laquelle vous opérez. Cela pourrait être n'importe laquelle des portées par défaut ou des portées enfants qui sont créées.                                                                                                                                                 |
| Script | C'est une portée temporaire qui s'applique à tous les scripts en cours d'exécution. Elle s'applique uniquement au script et à son contenu. D'autres scripts et tout ce qui est en dehors ne sauront pas qu'elle existe. Pour le script, sa portée est la portée locale.                                  |

Cela nous importe si nous ne voulons pas que quoi que ce soit en dehors de la portée dans laquelle nous exécutons le script accède à son contenu. De plus, nous pouvons avoir des portées enfants créées dans les portées principales. Par exemple, lorsque vous exécutez un script, la portée du script est instanciée, puis toute fonction qui est appelée peut également générer une portée enfant entourant cette fonction et ses variables incluses. Si nous voulions nous assurer que le contenu de cette fonction spécifique ne soit pas accessible au reste du script ou à la session PowerShell elle-même, nous pourrions modifier sa portée. C'est un sujet complexe et quelque chose au-dessus du niveau de ce module actuellement, mais nous avons pensé qu'il valait la peine d'être mentionné. Pour plus d'informations sur la Portée dans PowerShell, consultez la documentation ici.

***

### <mark style="color:blue;">Assembler le Tout</mark>

Maintenant que nous avons parcouru et créé nos pièces et parties, voyons tout ensemble.

#### Produit Final

```powershell
import-module ActiveDirectory

<# 
.Description  
Cette fonction effectue quelques tâches de reconnaissance simples pour l'utilisateur. Nous importons le module puis émettons la commande 'Get-Recon' pour récupérer notre sortie. Chaque variable et ligne dans la fonction et le script sont commentées pour votre compréhension. Pour l'instant, cela ne fonctionne que sur l'hôte local à partir duquel vous l'exécutez, et la sortie sera envoyée à un fichier nommé 'recon.txt' sur le Bureau de l'utilisateur qui a ouvert le shell. Les fonctions de Recon à distance arrivent bientôt !  

.Example  
Après avoir importé le module, exécutez "Get-Recon"
'Get-Recon


    Directory: C:\Users\MTanaka\Desktop


Mode                 LastWriteTime         Length Name                                                                                                                                        
----                 -------------         ------ ----                                                                                                                                        
-a----         11/3/2022  12:46 PM              0 recon.txt '

.Notes  
Les fonctions de Recon à distance arrivent bientôt ! Ce script sert de notre introduction initiale à l'écriture de fonctions et scripts et à la création de modules PowerShell.  

#>
function Get-Recon {  
    # Collecter le nom d'hôte de notre PC
    $Hostname = $env:ComputerName  
    # Collecter la configuration IP
    $IP = ipconfig
    # Collecter les informations de domaine de base
    $Domain = Get-ADDomain 
    # Sortir les utilisateurs qui se sont connectés et ont construit une structure de répertoire de base dans "C:\Users"
    $Users = Get-ChildItem C:\Users\
    # Créer un nouveau fichier pour placer nos résultats de reconnaissance
    new-Item ~\Desktop\recon.txt -ItemType File 
    # Une variable pour contenir les résultats de nos autres variables 
    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
    # Ça fait le truc 
    Add-Content ~\Desktop\recon.txt $Vars
  } 

Export-ModuleMember -Function Get-Recon -Variable Hostname 
```

Et voilà, notre fichier de module complet. Notre utilisation de l'aide basée sur les commentaires, des fonctions, des variables et de la protection du contenu fait un script dynamique et clair à lire. À partir de là, nous pouvons enregistrer ce fichier dans notre répertoire de Module que nous avons créé et l'importer depuis PowerShell pour utilisation.

***

### <mark style="color:blue;">Importer le Module Pour Utilisation</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Import-Module 'C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon.psm1`

PS C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon> get-module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Con...
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...
Script     0.0        quick-recon                         Get-Recon
```
{% endcode %}

Parfait. Nous pouvons voir que notre module a été importé en utilisant la cmdlet `Import-Module`, et pour nous assurer qu'il était chargé dans notre session, nous avons exécuté la cmdlet `Get-Module`. Elle nous a montré que notre module `quick-recon` a été importé et a la commande `Get-Recon` qui pourrait être exportée. Nous pouvons également tester l'aide basée sur les commentaires en essayant d'exécuter `Get-Help` contre notre module.

### Validation de l'Aide

```powershell
PS C:\htb> get-help get-recon

NAME
    Get-Recon

SYNOPSIS


SYNTAX
    Get-Recon [<CommonParameters>]


DESCRIPTION
    Cette fonction effectue quelques tâches de reconnaissance simples pour l'utilisateur. Nous importons simplement le module puis émettons la commande 'Get-Recon' pour récupérer notre sortie. Chaque variable et ligne dans la fonction et le script sont commentées pour votre compréhension. Pour l'instant, cela ne fonctionne que sur l'hôte local à partir duquel vous l'exécutez, et la sortie sera envoyée à un fichier nommé 'recon.txt' sur le Bureau de l'utilisateur qui a ouvert le shell. Les fonctions de Recon à distance arrivent bientôt !


RELATED LINKS

REMARKS
    Pour voir les exemples, tapez : "get-help Get-Recon -examples."
    Pour plus d'informations, tapez : "get-help Get-Recon -detailed."
    Pour des informations techniques, tapez : "get-help Get-Recon -full."
```
