# Working with the Windows Event Log

## <mark style="color:red;">Travailler avec les Journaux d'Événements Windows</mark>

### <mark style="color:blue;">Introduction</mark>

Du point de vue d'un analyste SOC ou d'un administrateur informatique, surveiller, collecter et catégoriser les événements se produisant sur toutes les machines du réseau est une source d'information inestimable pour les défenseurs qui analysent et protègent proactivement leur réseau contre les activités suspectes.&#x20;

D'autre part, les attaquants peuvent y voir une opportunité d'obtenir un aperçu de l'environnement cible, de perturber le flux d'informations et de dissimuler leurs traces.

***

### <mark style="color:blue;">Qu'est-ce que le Journal d'Événements Windows ?</mark>

{% hint style="info" %}
Le premier qui doit être expliqué est la définition d'un événement. En termes simples, un événement est toute action ou occurrence qui peut être identifiée et classée par le matériel ou le logiciel d'un système. Les événements peuvent être générés ou déclenchés de diverses manières, notamment :
{% endhint %}

#### <mark style="color:green;">Événements Générés par l'Utilisateur</mark>

* Mouvement d'une souris, frappe sur un clavier, autres périphériques contrôlés par l'utilisateur, etc.

#### <mark style="color:green;">Événements Générés par l'Application</mark>

* Mises à jour d'application, plantages, utilisation/consommation de mémoire, etc.

#### <mark style="color:green;">Événements Générés par le Système</mark>

* Temps de fonctionnement du système, mises à jour du système, chargement/déchargement de pilotes, connexion utilisateur, etc.

#### <mark style="color:green;">Définition de la Journalisation d'Événements selon Microsoft :</mark>

{% hint style="info" %}
Fournit un moyen standard et centralisé pour les applications (et le système d'exploitation) d'enregistrer les événements matériels et logiciels importants."
{% endhint %}

Windows tente de résoudre ce problème en fournissant une approche standardisée pour enregistrer, stocker et gérer les événements et les informations d'événements via un service connu sous le nom de Journal d'Événements Windows.&#x20;

***

### <mark style="color:blue;">Catégories et Types de Journaux d'Événements</mark>

Les quatre principales catégories de journaux incluent application, sécurité, installation et système. Un autre type de catégorie existe également appelé événements transférés.

<table data-full-width="true"><thead><tr><th>Catégorie de Journal</th><th>Description du Journal</th></tr></thead><tbody><tr><td>Journal Système</td><td>Le journal système contient des événements liés au système Windows et à ses composants. Un événement au niveau du système pourrait être un service qui échoue au démarrage.</td></tr><tr><td>Journal Sécurité</td><td>Auto-explicatif ; ceux-ci incluent des événements liés à la sécurité tels que les connexions réussies et échouées, et la création/suppression de fichiers. Ceux-ci peuvent être utilisés pour détecter divers types d'attaques que nous couvrirons dans les modules ultérieurs.</td></tr><tr><td>Journal Application</td><td>Cela stocke les événements liés à tout logiciel/application installé sur le système. Par exemple, si Slack a du mal à démarrer, cela sera enregistré dans ce journal.</td></tr><tr><td>Journal Installation</td><td>Ce journal contient tous les événements générés lors de l'installation du système d'exploitation Windows. Dans un environnement de domaine, les événements liés à Active Directory seront enregistrés dans ce journal sur les hôtes contrôleurs de domaine.</td></tr><tr><td>Événements Transférés</td><td>Journaux qui sont transférés à partir d'autres hôtes du même réseau.</td></tr></tbody></table>

***

### <mark style="color:blue;">Types d'Événements</mark>

Il existe cinq types d'événements qui peuvent être enregistrés sur les systèmes Windows :

<table data-full-width="true"><thead><tr><th>Type d'Événement</th><th>Description de l'Événement</th></tr></thead><tbody><tr><td>Erreur</td><td>Indique qu'un problème majeur s'est produit, comme un service qui ne parvient pas à se charger au démarrage.</td></tr><tr><td>Avertissement</td><td>Un journal moins significatif mais qui peut indiquer un problème possible à l'avenir. Un exemple est un espace disque faible. Un événement d'avertissement sera enregistré pour noter qu'un problème peut survenir à l'avenir. Un événement d'avertissement se produit généralement lorsqu'une application peut récupérer de l'événement sans perdre de fonctionnalité ou de données.</td></tr><tr><td>Information</td><td>Enregistré lors du fonctionnement réussi d'une application, d'un pilote ou d'un service, comme lorsqu'un pilote réseau se charge avec succès. Généralement, toutes les applications de bureau n'enregistrent pas un événement chaque fois qu'elles démarrent, car cela pourrait entraîner une quantité considérable de "bruit" supplémentaire dans les journaux.</td></tr><tr><td>Audit Réussi</td><td>Enregistré lorsqu'une tentative d'accès de sécurité auditée réussit, comme lorsqu'un utilisateur se connecte à un système.</td></tr><tr><td>Audit Échoué</td><td>Enregistré lorsqu'une tentative d'accès de sécurité auditée échoue, comme lorsqu'un utilisateur tente de se connecter mais tape son mot de passe incorrectement. De nombreux événements d'échec d'audit pourraient indiquer une attaque, comme le Password Spraying.</td></tr></tbody></table>

### <mark style="color:blue;">Niveaux de Gravité des Événements</mark>

Chaque journal peut avoir l'un des cinq niveaux de gravité associés, désigné par un nombre :

<table data-full-width="true"><thead><tr><th>Niveau de Gravité</th><th>Niveau #</th><th>Description</th></tr></thead><tbody><tr><td>Verbose</td><td>5</td><td>Messages de progression ou de succès.</td></tr><tr><td>Information</td><td>4</td><td>Un événement qui s'est produit sur le système mais n'a causé aucun problème.</td></tr><tr><td>Avertissement</td><td>3</td><td>Un problème potentiel qu'un administrateur système devrait examiner.</td></tr><tr><td>Erreur</td><td>2</td><td>Un problème lié au système ou au service qui ne nécessite pas d'attention immédiate.</td></tr><tr><td>Critique</td><td>1</td><td>Cela indique un problème significatif lié à une application ou à un système qui nécessite une attention urgente de la part d'un administrateur système et qui, s'il n'est pas résolu, pourrait entraîner une instabilité du système ou de l'application.</td></tr></tbody></table>

### <mark style="color:blue;">Éléments d'un Journal d'Événements Windows</mark>

Le Journal d'Événements Windows fournit des informations sur les événements matériels et logiciels sur un système Windows. Tous les journaux d'événements sont stockés dans un format standard et incluent les éléments suivants :

* **Nom du journal** : Comme discuté ci-dessus, le nom du journal d'événements où les événements seront écrits. Par défaut, les événements sont enregistrés pour le système, la sécurité et les applications.
* **Date/heure de l'événement** : Date et heure auxquelles l'événement s'est produit
* **Catégorie de tâche** : Le type de journal d'événements enregistré
* **ID d'événement** : Un identifiant unique pour que les administrateurs système identifient un événement enregistré spécifique
* **Source** : D'où provient le journal, généralement le nom d'un programme ou d'une application logicielle
* **Niveau** : Niveau de gravité de l'événement. Il peut s'agir d'information, d'erreur, de verbose, d'avertissement, de critique
* **Utilisateur** : Nom d'utilisateur de la personne connectée à l'hôte lorsque l'événement s'est produit
* **Ordinateur** : Nom de l'ordinateur où l'événement est enregistré

***

### <mark style="color:blue;">Détails Techniques du Journal d'Événements Windows</mark>

Le Journal d'Événements Windows est géré par les services EventLog. Sur un système Windows, le nom d'affichage du service est Journal d'Événements Windows, et il s'exécute dans le processus hôte de service svchost.exe. Il est configuré pour démarrer automatiquement au démarrage du système par défaut. Il est difficile d'arrêter le service EventLog car il a plusieurs services de dépendance. S'il est arrêté, cela causera probablement une instabilité système significative. Par défaut, les Journaux d'Événements Windows sont stockés dans `C:\Windows\System32\winevt\logs` avec l'extension de fichier `.evtx`.

```powershell
PS C:\htb> ls C:\Windows\System32\winevt\logs

    Directory: C:\Windows\System32\winevt\logs

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/16/2022   2:19 PM        7409664 Application.evtx
-a----         6/14/2022   8:20 PM          69632 HardwareEvents.evtx
-a----         6/14/2022   8:20 PM          69632 Internet Explorer.evtx
-a----         6/14/2022   8:20 PM          69632 Key Management Service.evtx
-a----         8/23/2022   7:01 PM          69632 Microsoft-Client-License-Flexible-Platform%4Admin.evtx
-a----        11/16/2022   2:19 PM        1052672 Microsoft-Client-Licensing-Platform%4Admin.evtx
```

{% hint style="info" %}
Nous pouvons interagir avec le Journal d'Événements Windows en utilisant l'application GUI Windows Event Viewer via l'utilitaire en ligne de commande wevtutil, ou en utilisant le cmdlet PowerShell Get-WinEvent.&#x20;

Les deux wevtutil et Get-WinEvent peuvent être utilisés pour interroger les Journaux d'Événements sur les systèmes Windows locaux et distants via cmd.exe ou PowerShell.
{% endhint %}

***

### <mark style="color:blue;">Interagir avec le Journal d'Événements Windows - wevtutil</mark>

L'utilitaire en ligne de commande wevtutil peut être utilisé pour récupérer des informations sur les journaux d'événements. Il peut également être utilisé pour exporter, archiver et effacer les journaux, entre autres commandes.

#### Wevtutil sans Paramètres

```powershell
C:\htb> wevtutil /?

Utilitaire de Ligne de Commande des Événements Windows.

Permet de récupérer des informations sur les journaux d'événements et les éditeurs, installer
et désinstaller les manifestes d'événements, exécuter des requêtes, et exporter, archiver et effacer les journaux.

Utilisation :

Vous pouvez utiliser soit la version courte (par exemple, ep /uni) ou longue (par exemple,
enum-publishers /unicode) des noms de commande et d'option. Les commandes,
options et valeurs d'option ne sont pas sensibles à la casse.

Les variables sont notées en MAJUSCULES.

wevtutil COMMANDE [ARGUMENT [ARGUMENT] ...] [/OPTION:VALEUR [/OPTION:VALEUR] ...]

Commandes :

el | enum-logs          Lister les noms de journaux.
gl | get-log            Obtenir les informations de configuration du journal.
sl | set-log            Modifier la configuration d'un journal.
ep | enum-publishers    Lister les éditeurs d'événements.
gp | get-publisher      Obtenir les informations de configuration de l'éditeur.
im | install-manifest   Installer les éditeurs et journaux d'événements à partir du manifeste.
um | uninstall-manifest Désinstaller les éditeurs et journaux d'événements du manifeste.
qe | query-events       Interroger les événements d'un journal ou fichier journal.
gli | get-log-info      Obtenir les informations d'état du journal.
epl | export-log        Exporter un journal.
al | archive-log        Archiver un journal exporté.
cl | clear-log          Effacer un journal.
```

#### <mark style="color:$success;">Énumération des Sources de Journaux</mark>

Nous pouvons utiliser le paramètre `el` pour énumérer les noms de tous les journaux présents sur un système Windows.

```cmd
C:\htb> wevtutil el

AMSI/Debug
AirSpaceChannel
Analytic
Application
DirectShowFilterGraph
DirectShowPluginControl
Els_Hyphenation/Analytic
EndpointMapper
FirstUXPerf-Analytic
ForwardedEvents
General Logging
HardwareEvents
```

#### Collecte d'Informations sur les Journaux

Avec le paramètre `gl`, nous pouvons afficher les informations de configuration pour un journal spécifique, notamment si le journal est activé ou non, la taille maximale, les permissions et où le journal est stocké sur le système.

```cmd
C:\htb> wevtutil gl "Windows PowerShell"

name: Windows PowerShell
enabled: true
type: Admin
owningPublisher:
isolation: Application
channelAccess: O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Windows PowerShell.evtx
  retention: false
  autoBackup: false
  maxSize: 15728640
publishing:
  fileMax: 1
```

Le paramètre `gli` nous donnera des informations d'état spécifiques sur le journal ou le fichier journal, telles que l'heure de création, les heures de dernier accès et d'écriture, la taille du fichier, le nombre d'enregistrements de journal, et plus encore.

```cmd
C:\htb> wevtutil gli "Windows PowerShell"

creationTime: 2020-10-06T16:57:38.617Z
lastAccessTime: 2022-10-26T19:05:21.533Z
lastWriteTime: 2022-10-26T19:05:21.533Z
fileSize: 11603968
attributes: 32
numberOfLogRecords: 9496
oldestRecordNumber: 1
```

#### <mark style="color:$success;">Interrogation des Événements</mark>

Il existe de nombreuses façons d'interroger les événements. Par exemple, disons que nous voulons afficher les 5 événements les plus récents du journal Sécurité au format texte. Un accès administrateur local est nécessaire pour cette commande.

```cmd
C:\htb> wevtutil qe Security /c:5 /rd:true /f:text

Event[0]
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2022-11-16T14:54:13.2270000Z
  Event ID: 4799
  Task: Security Group Management
  Level: Information
  Opcode: Info
  Keyword: Audit Success
  User: N/A
  User Name: N/A
  Computer: ICL-WIN11.greenhorn.corp
  Description:
Une appartenance à un groupe local activé pour la sécurité a été énumérée.

Subject:
        Security ID:            S-1-5-18
        Account Name:           ICL-WIN11$
        Account Domain:         GREENHORN
        Logon ID:               0x3E7

Group:
        Security ID:            S-1-5-32-544
        Group Name:             Administrators
        Group Domain:           Builtin

Process Information:
        Process ID:             0x56c
        Process Name:           C:\Windows\System32\svchost.exe
```

#### <mark style="color:$success;">Exportation des Événements</mark>

Nous pouvons également exporter des événements d'un journal spécifique pour un traitement hors ligne. Un accès administrateur local est également nécessaire pour effectuer cette exportation.

```cmd
C:\htb> wevtutil epl System C:\system_export.evtx
```

***

### <mark style="color:blue;">Interagir avec le Journal d'Événements Windows - PowerShell</mark>

De même, nous pouvons interagir avec les Journaux d'Événements Windows en utilisant le cmdlet PowerShell Get-WinEvent. Comme avec les exemples wevtutil, certaines commandes nécessitent un accès de niveau administrateur local.

#### <mark style="color:$success;">PowerShell - Liste de Tous les Journaux</mark>

Pour commencer, nous pouvons lister tous les journaux sur l'ordinateur, en nous donnant le nombre d'enregistrements dans chaque journal.

```powershell
PS C:\htb> Get-WinEvent -ListLog *

LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular            15728640         657 Windows PowerShell
Circular            20971520       10713 System
Circular            20971520       26060 Security
Circular            20971520           0 Key Management Service
Circular             1052672           0 Internet Explorer
Circular            20971520           0 HardwareEvents
Circular            20971520        6202 Application
```

#### <mark style="color:$success;">Détails du Journal Sécurité</mark>

Nous pouvons également lister des informations sur un journal spécifique. Ici, nous pouvons voir la taille du journal Sécurité.

```powershell
PS C:\htb> Get-WinEvent -ListLog Security

LogMode   MaximumSizeInBytes RecordCount LogName
-------   ------------------ ----------- -------
Circular            20971520       26060 Security
```

#### <mark style="color:$success;">Interrogation des Cinq Derniers Événements</mark>

Si nous voulons obtenir d'abord les journaux plus anciens, nous pouvons inverser l'ordre pour lister d'abord les plus anciens en utilisant le paramètre `-Oldest`.

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message

Un compte a été déconnecté.

Subject:
        Security ID:            S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-6052
        Account Name:           sshd_6052
        Account Domain:         VIRTUAL USERS
        Logon ID:               0x8E787

Logon Type:                     5

Cet événement est généré lorsqu'une session de connexion est détruite. Il peut être positivement corrélé avec un événement de connexion en utilisant la valeur Logon ID. Les Logon ID sont uniquement uniques entre les redémarrages sur le même ordinateur.
```
{% endcode %}

#### <mark style="color:$success;">Filtrage des Échecs de Connexion</mark>

Nous pouvons approfondir et examiner des ID d'événements spécifiques dans des journaux spécifiques. Disons que nous voulons seulement examiner les échecs de connexion dans le journal Sécurité, en vérifiant l'ID d'événement 4625 : Un compte n'a pas réussi à se connecter. À partir de là, nous pourrions utiliser le paramètre `-ExpandProperty` pour approfondir des événements spécifiques, lister les journaux du plus ancien au plus récent, etc.

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625'}

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
11/16/2022 2:53:16 PM          4625 Information      Un compte n'a pas réussi à se connecter....
11/16/2022 2:53:16 PM          4625 Information      Un compte n'a pas réussi à se connecter....
11/16/2022 2:53:12 PM          4625 Information      Un compte n'a pas réussi à se connecter....
```
{% endcode %}

#### <mark style="color:$success;">Filtrage par Niveau de Gravité</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message

Le système a redémarré sans s'être arrêté proprement au préalable. Cette erreur pourrait se produire si le système a cessé de répondre, s'est planté ou a perdu l'alimentation de manière inattendue.
```
{% endcode %}
