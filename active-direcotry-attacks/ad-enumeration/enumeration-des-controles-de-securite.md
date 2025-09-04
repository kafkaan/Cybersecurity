# Énumération des Contrôles de Sécurité

***

## <mark style="color:red;">**Windows Defender**</mark>

{% hint style="warning" %}
Windows Defender (renommé Microsoft Defender après la mise à jour de mai 2020 de Windows 10) s'est considérablement amélioré et, par défaut, bloque des outils comme **PowerView**.&#x20;

Nous pouvons utiliser la commande PowerShell intégrée **Get-MpComputerStatus** pour vérifier l’état actuel de Defender. Par exemple, le paramètre `RealTimeProtectionEnabled` défini sur `True` indique que la protection en temps réel est activée.
{% endhint %}

```powershell
PS C:\htb> Get-MpComputerStatus
```

Sortie (extrait) :

* **RealTimeProtectionEnabled** : True
* **AntivirusEnabled** : True
* **AntivirusSignatureVersion** : 1.323.392.0

***

## <mark style="color:red;">**AppLocker**</mark>

{% hint style="warning" %}
AppLocker est une solution de liste blanche proposée par Microsoft. Elle permet aux administrateurs de contrôler quels programmes ou fichiers peuvent être exécutés par les utilisateurs. AppLocker offre un contrôle précis sur les exécutables, scripts, fichiers d’installation, DLLs, applications packagées, etc. Par exemple, il est courant que les organisations bloquent **cmd.exe**, **PowerShell.exe** et l’accès en écriture à certains répertoires. Toutefois, ces restrictions peuvent être contournées.
{% endhint %}

Un exemple typique est le blocage de **PowerShell.exe** dans le chemin suivant :

```
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
```

Cependant, il est possible de l’exécuter depuis un autre emplacement, comme :

```
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

**Exemple : Vérification des règles AppLocker**

```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Sortie (extrait) :

* **Action : Deny** pour `%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`
* **Action : Allow** pour les fichiers du dossier `%ProgramFiles%` ou `%Windir%`.

***

## <mark style="color:red;">**Mode Langage Contraint de PowerShell**</mark>

Le **Constrained Language Mode** de PowerShell restreint de nombreuses fonctionnalités essentielles, comme les objets COM, certains types .NET approuvés, et d’autres fonctionnalités avancées. Pour vérifier si nous sommes en mode complet ou restreint :

```powershell
PS C:\htb> $ExecutionContext.SessionState.LanguageMode
```

Sortie : `ConstrainedLanguage` (Mode restreint)

***

## <mark style="color:red;">**LAPS (Local Administrator Password Solution)**</mark>

{% hint style="warning" %}
La solution Microsoft **LAPS** randomise et fait tourner les mots de passe administrateur locaux sur les hôtes Windows, empêchant les déplacements latéraux. Nous pouvons identifier quels utilisateurs du domaine peuvent lire ces mots de passe LAPS et quels hôtes n'ont pas LAPS installé. L’outil **LAPSToolkit** facilite cette tâche grâce à des fonctions comme **Find-LAPSDelegatedGroups**, qui permet d’identifier les groupes autorisés à lire les mots de passe LAPS.
{% endhint %}

<mark style="color:green;">**Exemple : Utilisation de Find-LAPSDelegatedGroups**</mark>

```powershell
PS C:\htb> Find-LAPSDelegatedGroups
```

Sortie (extrait) :

* **OU=Servers,DC=INLANEFREIGHT,DC=LOCAL** : `INLANEFREIGHT\Domain Admins`
* **OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL** : `INLANEFREIGHT\LAPS Admins`

Cela montre les unités organisationnelles (OUs) et les groupes qui peuvent lire les mots de passe LAPS.

***
