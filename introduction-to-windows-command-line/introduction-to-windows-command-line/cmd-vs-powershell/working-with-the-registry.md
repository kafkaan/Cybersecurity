# Working with the Registry

## <mark style="color:red;">Working with the Registry</mark>

***

### <mark style="color:blue;">What Is The Windows Registry?</mark>

At its core, the `Registry` can be considered a hierarchal tree that contains two essential elements: `keys` and `values`.&#x20;

This tree stores all the required information for the operating system and the software installed to run under subtrees (think of them as branches of a tree).&#x20;

This information can be anything from settings to installation directories to specific options and values that determine how everything functions. As Pentesters, the Registry is a great spot to find helpful information, plant persistence, and more.&#x20;

[MITRE](https://attack.mitre.org/techniques/T1112/) provides many great examples of what a threat actor can do with access (locally or remotely) to a host's registry hive.

***

#### <mark style="color:green;">What are Keys</mark>

`Keys`, in essence, are containers that represent a specific component of the PC. Keys can contain other keys and values as data.&#x20;

These entries can take many forms, and naming contexts only require that a Key be named using alphanumeric (printable) characters and is not case-sensitive. As a visual example of Keys, if we look at the image below, each folder within the `Green rectangle` is a Key and contains sub-keys.

**Keys (Green)**

![Registry Editor showing path: HKEY\_LOCAL\_MACHINE\SOFTWARE\Adobe\Adobe Acrobat\10.0\Installer. Right pane displays 'DisableMaintenance' with value 1.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/167/registry.png)

#### <mark style="color:blue;">Registry Key Files</mark>

A host systems Registry `root keys` are stored in several different files and can be accessed from `C:\Windows\System32\Config\`. Along with these Key files, registry hives are held throughout the host in various other places.

<mark style="color:orange;">**Root Registry Keys**</mark>

```powershell
PS C:\htb> Get-ChildItem C:\Windows\System32\config\

    Directory: C:\Windows\System32\config

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----           12/7/2019  4:14 AM                Journal
d----           12/7/2019  4:14 AM                RegBack
d----           4/28/2021 11:43 AM                systemprofile
d----           9/18/2021 12:22 AM                TxR
-a---          10/12/2022 10:06 AM         786432 BBI
-a---           1/20/2021  5:13 PM          28672 BCD-Template
-a---          10/18/2022 11:14 AM       38273024 COMPONENTS
-a---          10/12/2022 10:06 AM        1048576 DEFAULT
-a---          10/15/2022  9:33 PM       13463552 DRIVERS
-a---           1/27/2021  2:54 PM          32768 ELAM
-a---          10/12/2022 10:06 AM         131072 SAM
-a---          10/12/2022 10:06 AM          65536 SECURITY
-a---          10/12/2022 10:06 AM      168034304 SOFTWARE
-a---          10/12/2022 10:06 AM       29884416 SYSTEM
-a---          10/12/2022 10:06 AM           1623 VSMIDK
```

For a detailed list of all Registry Hives and their supporting files within the OS, we can look [HERE](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives). Now let's discuss Values within the Registry.

#### <mark style="color:green;">What Are Values</mark>

Les **Valeurs** sont les données stockées à l'intérieur des clés du registre.

***

#### Une Valeur est composée de 3 éléments :

| Élément     | Description                | Exemple                  |
| ----------- | -------------------------- | ------------------------ |
| **Nom**     | L'identifiant de la valeur | `Version`                |
| **Type**    | Le format de la donnée     | `REG_SZ`, `REG_DWORD`... |
| **Données** | Le contenu réel            | `1.0.0`                  |

***

#### Analogie simple :

Imagine le registre comme une **armoire** :

Armoire = Registre\
Tiroir = Clé (Key)\
Sous-tiroir = Sous-clé (SubKey)\
Étiquette = Valeur (Value) ← c'est ça dont on parle

**Values**

![Registry Editor showing path: HKEY\_LOCAL\_MACHINE\SOFTWARE\Adobe\Adobe Acrobat\10.0\Installer. Right pane displays 'DisableMaintenance' with value 1.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/167/registry-values.png)

We can reference the complete list of Registry Key Values [HERE](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types). In all, there are 11 different value types that can be configured.

***

#### <mark style="color:green;">Registry Hives</mark>

Chaque hôte Windows possède un ensemble de clés de registre prédéfinies. Voici le détail de chaque ruche :

<table data-full-width="true"><thead><tr><th>Nom</th><th>Abréviation</th><th>Contenu</th></tr></thead><tbody><tr><td><code>HKEY_LOCAL_MACHINE</code></td><td><strong>HKLM</strong></td><td>Contient les infos sur l'<strong>état physique</strong> de l'ordinateur : matériel, système d'exploitation, types de bus, mémoire, pilotes de périphériques, etc.</td></tr><tr><td><code>HKEY_CURRENT_CONFIG</code></td><td><strong>HKCC</strong></td><td>Contient les enregistrements du <strong>profil matériel actuel</strong> de l'hôte. Montre les différences entre la configuration actuelle et celle par défaut. C'est une redirection vers la clé <code>CurrentControlSet</code> de HKLM.</td></tr><tr><td><code>HKEY_CLASSES_ROOT</code></td><td><strong>HKCR</strong></td><td>Définit les <strong>types de fichiers</strong>, les extensions d'interface utilisateur et les paramètres de compatibilité ascendante (ex: quelle application ouvre quel fichier).</td></tr><tr><td><code>HKEY_CURRENT_USER</code></td><td><strong>HKCU</strong></td><td>Contient les paramètres <strong>OS et logiciels spécifiques à l'utilisateur connecté</strong>. Les préférences utilisateur et les paramètres de profil itinérant (<strong>Roaming Profile</strong>) sont stockés ici.</td></tr><tr><td><code>HKEY_USERS</code></td><td><strong>HKU</strong></td><td>Contient le profil utilisateur <strong>par défaut</strong> et les paramètres de configuration de <strong>tous les utilisateurs</strong> du PC local.</td></tr></tbody></table>

***

#### Moyen mémo-technique simple :

* **HKLM** → la **Machine** (matériel + OS)
* **HKCC** → la **Config actuelle** du matériel
* **HKCR** → les **types de fichiers** (.pdf, .exe, .txt...)
* **HKCU** → l'utilisateur **connecté maintenant**
* **HKU** → **tous** les utilisateurs du PC

There are other predefined keys for the Registry, but they are specific to certain versions and regional settings in Windows. For more information on those entries and Registry keys in general, check out the documentation provided by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys)

#### <mark style="color:green;">Why Is The Information Stored Within The Registry Important?</mark>

As a pentester, the Registry can be a treasure trove of information that can help us further our engagements.&#x20;

Everything from what software is installed, current OS revision, pertinent security settings, control of Defender, and more can be found in the Registry.&#x20;

Can we find all of this information in other places? Yes. But there is no better single point to find all of it and have the ability to make widespread changes to the host simultaneously.&#x20;

From an offensive perspective, the Registry is hard for Defenders to protect. The hives are enormous and filled with hundreds of entries. Finding a singular change or addition among the hives is like hunting for a needle in a haystack (unless they keep solid backups of their configurations and host states). Having a general understanding of the Registry and where key values are within can help us take action quicker and for defenders spot any issues sooner.

***

### <mark style="color:blue;">How Do We Access the Information?</mark>

From the CLI, we have several options to access the Registry and manage our keys. The first is using [reg.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg). `Reg` is a dos executable explicitly made for use in managing Registry settings. The second is using the `Get-Item` and `Get-ItemProperty` cmdlets to read keys and values. If we wish to make a change, the use of New-ItemProperty will do the trick.

#### <mark style="color:green;">Querying Registry Entries</mark>

We will look at using `Get-Item` and `Get-ChildItem` first. Below we can see the output from using Get-Item and piping the result to Select-Object.

**Get-Item**

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property  

SecurityHealth
RtkAudUService
WavesSvc
DisplayLinkTrayApp
LogiOptions
Acrobat Assistant 8.0
(default)
Focusrite Notifier
AdobeGCInvoker-1.0
```
{% endcode %}

It's a simple output and only shows us the name of the services/applications currently running. If we wished to see each key and object within a hive, we could also use `Get-ChildItem` with the `-Recurse` parameter like so:

**Recursive Search**

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse

Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
<SNIP>
Name                           Property
----                           --------
7zFM.exe                       (default) : C:\Program Files\7-Zip\7zFM.exe
                               Path      : C:\Program Files\7-Zip\
Acrobat.exe                    (default) : C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe
                               Path      : C:\Program Files\Adobe\Acrobat DC\Acrobat\
AcrobatInfo.exe                (default) : C:\Program Files\Adobe\Acrobat DC\Acrobat\AcrobatInfo.exe
                               Path      : C:\Program Files\Adobe\Acrobat DC\Acrobat\
AcroDist.exe                   Path      : C:\Program Files\Adobe\Acrobat DC\Acrobat\
                               (default) : C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrodist.exe
Ahk2Exe.exe                    (default) : C:\Program Files\AutoHotkey\Compiler\Ahk2Exe.exe
AutoHotkey.exe                 (default) : C:\Program Files\AutoHotkey\AutoHotkey.exe
chrome.exe                     (default) : C:\Program Files\Google\Chrome\Application\chrome.exe
                               Path      : C:\Program Files\Google\Chrome\Application
cmmgr32.exe                    CmNative          : 2
                               CmstpExtensionDll : C:\Windows\System32\cmcfg32.dll
CNMNSST.exe                    (default) : C:\Program Files (x86)\Canon\IJ Network Scanner Selector EX\CNMNSST.exe
                               Path      : C:\Program Files (x86)\Canon\IJ Network Scanner Selector EX
devenv.exe                     (default) : "C:\Program Files\Microsoft Visual
                               Studio\2022\Community\common7\ide\devenv.exe"
dfshim.dll                     UseURL : 1
excel.exe                      (default) : C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE
                               Path      : C:\Program Files\Microsoft Office\Root\Office16\
                               UseURL    : 1
                               SaveURL   : 1
fsquirt.exe                    DropTarget : {047ea9a0-93bb-415f-a1c3-d7aeb3dd5087}
IEDIAG.EXE                     (default) : C:\Program Files\Internet Explorer\IEDIAGCMD.EXE
                               Path      : C:\Program Files\Internet Explorer;
IEDIAGCMD.EXE                  (default) : C:\Program Files\Internet Explorer\IEDIAGCMD.EXE
                               Path      : C:\Program Files\Internet Explorer;
IEXPLORE.EXE                   (default) : C:\Program Files\Internet Explorer\IEXPLORE.EXE
                               Path      : C:\Program Files\Internet Explorer;
install.exe                    BlockOnTSNonInstallMode : 1
javaws.exe                     (default) : C:\Program Files\Java\jre1.8.0_341\bin\javaws.exe
                               Path      : C:\Program Files\Java\jre1.8.0_341\bin
licensemanagershellext.exe     (default) : C:\Windows\System32\licensemanagershellext.exe
mip.exe                        (default) : C:\Program Files\Common Files\Microsoft Shared\Ink\mip.exe
mpc-hc64.exe                   (default) : C:\Program Files (x86)\K-Lite Codec Pack\MPC-HC64\mpc-hc64.exe
                               Path      : C:\Program Files (x86)\K-Lite Codec Pack\MPC-HC64
mplayer2.exe                   (default) : "C:\Program Files\Windows Media Player\wmplayer.exe"
                               Path      : C:\Program Files\Windows Media Player
MSACCESS.EXE                   (default) : C:\Program Files\Microsoft Office\Root\Office16\MSACCESS.EXE
                               Path      : C:\Program Files\Microsoft Office\Root\Office16\
                               UseURL    : 1
msedge.exe                     (default) : C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
                               Path      : C:\Program Files (x86)\Microsoft\Edge\Application

    Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe

Name                           Property
----                           --------
SupportedProtocols             http  :
                               https :
<SNIP>  
```
{% endcode %}

Now we snipped the output because it is expanding and showing each key and associated values within the `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion` key. We can make our output easier to read using the `Get-ItemProperty` cmdlet. Let's try that same query but with `Get-ItemProperty`.

**Get-ItemProperty**

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

SecurityHealth        : C:\Windows\system32\SecurityHealthSystray.exe
RtkAudUService        : "C:\Windows\System32\DriverStore\FileRepository\realtekservice.inf_amd64_85cff5320735903
                        d\RtkAudUService64.exe" -background
WavesSvc              : "C:\Windows\System32\DriverStore\FileRepository\wavesapo9de.inf_amd64_d350b8504310bbf5\W
                        avesSvc64.exe" -Jack
DisplayLinkTrayApp    : "C:\Program Files\DisplayLink Core Software\DisplayLinkTrayApp.exe" -basicMode
LogiOptions           : C:\Program Files\Logitech\LogiOptions\LogiOptions.exe /noui
Acrobat Assistant 8.0 : "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrotray.exe"
(default)             :
Focusrite Notifier    : "C:\Program Files\Focusriteusb\Focusrite Notifier.exe"
AdobeGCInvoker-1.0    : "C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGCInvokerUtility.exe"
PSPath                : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Curren
                        tVersion\Run
PSParentPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Curren
                        tVersion
PSChildName           : Run
PSProvider            : Microsoft.PowerShell.Core\Registry
```
{% endcode %}

<mark style="color:orange;">**Reg.exe**</mark>

```powershell
PS C:\htb> reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip

HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip
    Path64    REG_SZ    C:\Program Files\7-Zip\
    Path    REG_SZ    C:\Program Files\7-Zip\
```

We queried the `HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip` key with Reg.exe, which provided us with the associated values. We can see that `two` values are set, `Path` and `Path64`, the ValueType is a `Reg_SZ` value which specifies that it contains a Unicode or ASCII string, and that value is the path to 7-Zip `C:\Program Files\7-Zip\`.

***

### <mark style="color:blue;">Finding Info In The Registry</mark>

Pour les pentesters et administrateurs, chercher des données dans le registre est une compétence essentielle. C'est là que `Reg.exe` est très utile, notamment pour chercher des mots-clés comme `Password` ou `Username`.

***

La commande complète :

```
REG QUERY HKCU /F "password" /t REG_SZ /S /K
```

***

Décomposition :

| Partie          | Rôle                                                                                                       |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| `Reg Query`     | Appelle Reg.exe et lui dit qu'on veut **chercher** des données                                             |
| `HKCU`          | Définit **où chercher** → ici dans tout `HKEY_CURRENT_USER`                                                |
| `/f "password"` | Définit **ce qu'on cherche** → le mot "password"                                                           |
| `/t REG_SZ`     | Définit le **type de valeur** à chercher → REG\_SZ = texte simple. Sans ça, il cherche dans tous les types |
| `/s`            | Cherche **récursivement** dans toutes les sous-clés                                                        |
| `/k`            | Limite la recherche **uniquement aux noms de clés**                                                        |

***

En une phrase :

> Cette commande **parcourt tout HKCU** à la recherche du mot **"password"** uniquement dans les **noms de clés**, en descendant dans **tous les sous-dossiers**, en ne regardant que les valeurs de type **texte**. 🔍

**Searching With Reg Query**

```powershell-session
PS C:\htb>  REG QUERY HKCU /F "Password" /t REG_SZ /S /K

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Winlogon\PasswordExpiryNotification
    NotShownErrorTime    REG_SZ    08::23::24, 2022/10/19
    NotShownErrorReason    REG_SZ    GetPwdResetInfoFailed

End of search: 2 match(es) found.
```

***

#### <mark style="color:green;">Creating and Modifying Registry Keys and Values</mark>

{% hint style="info" %}
***

Les outils disponibles :
{% endhint %}

| Outil          | Cmdlets                                                        |
| -------------- | -------------------------------------------------------------- |
| **PowerShell** | `New-Item`, `Set-Item`, `New-ItemProperty`, `Set-ItemProperty` |
| **Reg.exe**    | `REG ADD`, `REG DELETE`...                                     |

{% hint style="info" %}
Le Scénario (Pentest) :

Tu as accès à une machine et tu veux **maintenir ton accès** (persistence). L'objectif est de faire exécuter ton payload automatiquement à la prochaine connexion de l'utilisateur.



Pourquoi `RunOnce` ?

```
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

> `RunOnce` = **exécute une fois** la valeur au prochain démarrage/connexion, puis la **supprime automatiquement** ← très discret pour un attaquant

***

Ce qu'on veut créer :

```
RunOnce\                                         ← KEY existante
  TestKey → C:\Users\htb-student\Downloads\payload.exe   ← VALUE à créer
```

***

Ce qui se passe concrètement :

1. Tu crées la clé **TestKey** dans RunOnce
2. Tu mets comme valeur le **chemin de ton payload**
3. L'utilisateur se reconnecte → Windows lit RunOnce → **exécute ton payload**
4. La clé se **supprime toute seule** → difficile à détecter 🔴

> C'est une technique classique de **persistence** en pentest : si tu perds l'accès, le payload se relance automatiquement à la prochaine session utilisateur. 🎯
{% endhint %}

**New Registry Key**

{% code fullWidth="true" %}
```powershell
PS C:\htb> New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey

    Hive: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

Name                           Property
----                           --------
TestKey   
```
{% endcode %}

We now have a new key within the RunOnce key. By specifying the `-Path` parameter, we avoid changing our location in the shell to where we want to add a key in the Registry, letting us work from anywhere as long as we specify the absolute path. Let's set a Property and a value now.

**Set New Registry Item Property**

{% code fullWidth="true" %}
```powershell
PS C:\htb>  New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"

access       : C:\Users\htb-student\Downloads\payload.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\
               TestKey
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
PSChildName  : TestKey
PSDrive      : HKCU
PSProvider   : Microsoft.PowerShell.Core\Registry

```
{% endcode %}

**TestKey Creation**

![Registry Editor showing path: HKEY\_CURRENT\_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey. Right pane displays 'access' with path to 'C:\Users\htb-student\Downloads\payload.exe'.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/167/testkeys.png)

If we wanted to add the same key/value pair using Reg.exe, we would do so like this:

{% code fullWidth="true" %}
```powershell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"  
```
{% endcode %}

**Delete Reg properties**

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"

PS C:\htb> Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey

```
{% endcode %}

***

<table data-full-width="true"><thead><tr><th width="62">#</th><th width="531">Commande</th><th>Description</th></tr></thead><tbody><tr><td>1</td><td><code>Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property</code></td><td>Affiche les noms des valeurs d'une clé</td></tr><tr><td>2</td><td><code>Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse</code></td><td>Liste toutes les sous-clés et valeurs récursivement</td></tr><tr><td>3</td><td><code>Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code></td><td>Affiche les valeurs d'une clé de façon lisible</td></tr><tr><td>4</td><td><code>reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip</code></td><td>Interroge une clé avec Reg.exe</td></tr><tr><td>5</td><td><code>REG QUERY HKCU /F "Password" /t REG_SZ /S /K</code></td><td>Cherche le mot "Password" dans les noms de clés de HKCU</td></tr><tr><td>6</td><td><code>Get-ChildItem C:\Windows\System32\config\</code></td><td>Liste les fichiers de ruches du registre</td></tr><tr><td>7</td><td><code>New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey</code></td><td>Crée une nouvelle clé dans le registre</td></tr><tr><td>8</td><td><code>New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name "access" -PropertyType String -Value "C:\...\payload.exe"</code></td><td>Crée une nouvelle valeur dans une clé</td></tr><tr><td>9</td><td><code>reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\...\payload.exe"</code></td><td>Crée une valeur avec Reg.exe</td></tr><tr><td>10</td><td><code>Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name "access"</code></td><td>Supprime une valeur du registre</td></tr><tr><td>11</td><td><code>Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey</code></td><td>Vérifie le contenu d'une clé après modification</td></tr></tbody></table>
