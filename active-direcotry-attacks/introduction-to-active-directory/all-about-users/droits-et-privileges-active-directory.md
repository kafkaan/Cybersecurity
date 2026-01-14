# Droits et Privilèges Active Directory

## <mark style="color:red;">Droits et Privilèges Active Directory</mark>

Les droits et privilèges sont les pierres angulaires de la gestion AD et, s'ils sont mal gérés, peuvent facilement conduire à des abus par des attaquants ou des testeurs d'intrusion. Les droits d'accès et les privilèges sont deux sujets importants dans AD (et en infosec en général), et nous devons comprendre la différence.

***

### <mark style="color:blue;">Différence entre Droits et Privilèges</mark>

**Les droits** sont généralement assignés aux utilisateurs ou aux groupes et concernent les permissions d'accès à un objet tel qu'un fichier.

**Les privilèges** accordent à un utilisateur la permission d'effectuer une action telle qu'exécuter un programme, éteindre un système, réinitialiser des mots de passe, etc.&#x20;

Les privilèges peuvent être assignés individuellement aux utilisateurs ou leur être conférés via l'appartenance à des groupes intégrés ou personnalisés.

Les ordinateurs Windows ont un concept appelé "User Rights Assignment" (Attribution des droits utilisateur), qui, bien qu'appelés droits, sont en réalité des types de privilèges accordés à un utilisateur. Nous discuterons de ceux-ci plus tard dans cette section.

Nous devons avoir une compréhension solide des différences entre droits et privilèges dans un sens plus large et précisément comment ils s'appliquent à un environnement AD.

***

### <mark style="color:blue;">Groupes AD Intégrés</mark>

AD contient de nombreux groupes de sécurité par défaut ou intégrés, dont certains accordent à leurs membres des droits et privilèges puissants qui peuvent être exploités pour escalader les privilèges au sein d'un domaine et finalement obtenir les privilèges Domain Admin ou SYSTEM sur un contrôleur de domaine (DC).

L'appartenance à beaucoup de ces groupes devrait être gérée de manière stricte car l'appartenance excessive aux groupes/privilèges est un défaut courant dans de nombreux réseaux AD que les attaquants cherchent à exploiter. Certains des groupes intégrés les plus courants sont listés ci-dessous.

***

#### <mark style="color:blue;">Tableau des Groupes Intégrés Principaux</mark>

**Account Operators (Opérateurs de Comptes)** Les membres peuvent créer et modifier la plupart des types de comptes, y compris ceux des utilisateurs, des groupes locaux et des groupes globaux, et les membres peuvent se connecter localement aux contrôleurs de domaine. Ils ne peuvent pas gérer le compte Administrateur, les comptes utilisateurs administratifs, ou les membres des groupes Administrators, Server Operators, Account Operators, Backup Operators ou Print Operators.

**Administrators (Administrateurs)** Les membres ont un accès complet et sans restriction à un ordinateur ou à un domaine entier s'ils sont dans ce groupe sur un contrôleur de domaine.

**Backup Operators (Opérateurs de Sauvegarde)** Les membres peuvent sauvegarder et restaurer tous les fichiers sur un ordinateur, indépendamment des permissions définies sur les fichiers. Les Backup Operators peuvent également se connecter et éteindre l'ordinateur. Les membres peuvent se connecter localement aux DC et doivent être considérés comme des Domain Admins. Ils peuvent faire des copies shadow de la base de données SAM/NTDS, qui, si elles sont prises, peuvent être utilisées pour extraire des informations d'identification et d'autres informations sensibles.

**DnsAdmins** Les membres ont accès aux informations DNS du réseau. Le groupe ne sera créé que si le rôle de serveur DNS est ou a été à un moment donné installé sur un contrôleur de domaine dans le domaine.

**Domain Admins (Administrateurs de Domaine)** Les membres ont un accès complet pour administrer le domaine et sont membres du groupe des administrateurs locaux sur toutes les machines jointes au domaine.

**Domain Computers (Ordinateurs du Domaine)** Tous les ordinateurs créés dans le domaine (à l'exception des contrôleurs de domaine) sont ajoutés à ce groupe.

**Domain Controllers (Contrôleurs de Domaine)** Contient tous les DC au sein d'un domaine. Les nouveaux DC sont ajoutés automatiquement à ce groupe.

**Domain Guests (Invités du Domaine)** Ce groupe inclut le compte Guest intégré du domaine. Les membres de ce groupe ont un profil de domaine créé lors de la connexion à un ordinateur joint au domaine en tant qu'invité local.

**Domain Users (Utilisateurs du Domaine)** Ce groupe contient tous les comptes utilisateurs dans un domaine. Un nouveau compte utilisateur créé dans le domaine est automatiquement ajouté à ce groupe.

**Enterprise Admins (Administrateurs d'Entreprise)** L'appartenance à ce groupe fournit un accès de configuration complet au sein du domaine. Le groupe n'existe que dans le domaine racine d'une forêt AD. Les membres de ce groupe se voient accorder la capacité d'effectuer des changements à l'échelle de la forêt tels que l'ajout d'un domaine enfant ou la création d'une approbation. Le compte Administrateur pour le domaine racine de la forêt est le seul membre de ce groupe par défaut.

**Event Log Readers (Lecteurs de Journaux d'Événements)** Les membres peuvent lire les journaux d'événements sur les ordinateurs locaux. Le groupe n'est créé que lorsqu'un hôte est promu contrôleur de domaine.

**Group Policy Creator Owners (Propriétaires Créateurs de Stratégie de Groupe)** Les membres créent, modifient ou suppriment des objets de stratégie de groupe dans le domaine.

**Hyper-V Administrators (Administrateurs Hyper-V)** Les membres ont un accès complet et sans restriction à toutes les fonctionnalités d'Hyper-V. S'il y a des DC virtuels dans le domaine, tous les administrateurs de virtualisation, tels que les membres d'Hyper-V Administrators, doivent être considérés comme des Domain Admins.

**IIS\_IUSRS** C'est un groupe intégré utilisé par Internet Information Services (IIS), à partir d'IIS 7.0.

**Pre–Windows 2000 Compatible Access (Accès Compatible Pré-Windows 2000)** Ce groupe existe pour la compatibilité ascendante pour les ordinateurs exécutant Windows NT 4.0 et versions antérieures. L'appartenance à ce groupe est souvent une configuration héritée restante. Cela peut conduire à des failles où n'importe qui sur le réseau peut lire des informations d'AD sans nécessiter un nom d'utilisateur et un mot de passe AD valides.

**Print Operators (Opérateurs d'Impression)** Les membres peuvent gérer, créer, partager et supprimer des imprimantes connectées aux contrôleurs de domaine dans le domaine ainsi que tous les objets imprimante dans AD. Les membres sont autorisés à se connecter localement aux DC et peuvent être utilisés pour charger un pilote d'imprimante malveillant et escalader les privilèges au sein du domaine.

**Protected Users (Utilisateurs Protégés)** Les membres de ce groupe bénéficient de protections supplémentaires contre le vol d'informations d'identification et les tactiques telles que l'abus de Kerberos.

**Read-only Domain Controllers (Contrôleurs de Domaine en Lecture Seule)** Contient tous les contrôleurs de domaine en lecture seule dans le domaine.

**Remote Desktop Users (Utilisateurs de Bureau à Distance)** Ce groupe est utilisé pour accorder aux utilisateurs et aux groupes la permission de se connecter à un hôte via Remote Desktop (RDP). Ce groupe ne peut pas être renommé, supprimé ou déplacé.

**Remote Management Users (Utilisateurs de Gestion à Distance)** Ce groupe peut être utilisé pour accorder aux utilisateurs un accès distant aux ordinateurs via Windows Remote Management (WinRM).

**Schema Admins (Administrateurs de Schéma)** Les membres peuvent modifier le schéma Active Directory, qui est la façon dont tous les objets dans AD sont définis. Ce groupe n'existe que dans le domaine racine d'une forêt AD. Le compte Administrateur pour le domaine racine de la forêt est le seul membre de ce groupe par défaut.

**Server Operators (Opérateurs de Serveur)** Ce groupe n'existe que sur les contrôleurs de domaine. Les membres peuvent modifier les services, accéder aux partages SMB et sauvegarder des fichiers sur les contrôleurs de domaine. Par défaut, ce groupe n'a aucun membre.

***

#### <mark style="color:blue;">Exemples de Détails de Groupes</mark>

Ci-dessous, nous avons fourni quelques sorties concernant les administrateurs de domaine et les opérateurs de serveur.

**Détails du groupe Server Operators :**

```powershell
PS C:\htb> Get-ADGroup -Identity "Server Operators" -Properties *

adminCount                      : 1
CanonicalName                   : INLANEFREIGHT.LOCAL/Builtin/Server Operators
CN                              : Server Operators
Created                         : 10/27/2021 8:14:34 AM
createTimeStamp                 : 10/27/2021 8:14:34 AM
Deleted                         : 
Description                     : Members can administer domain servers
DisplayName                     : 
DistinguishedName               : CN=Server Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
dSCorePropagationData           : {10/28/2021 1:47:52 PM, 10/28/2021 1:44:12 PM, 10/28/2021 1:44:11 PM, 10/27/2021 
                                  8:50:25 AM...}
GroupCategory                   : Security
GroupScope                      : DomainLocal
groupType                       : -2147483643
HomePage                        : 
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : 
LastKnownParent                 : 
ManagedBy                       : 
MemberOf                        : {}
Members                         : {}
Modified                        : 10/28/2021 1:47:52 PM
modifyTimeStamp                 : 10/28/2021 1:47:52 PM
Name                            : Server Operators
```

Comme nous pouvons le voir ci-dessus, l'état par défaut du groupe Server Operators est de n'avoir aucun membre et est un groupe local de domaine par défaut.

En revanche, le groupe Domain Admins vu ci-dessous a plusieurs membres et comptes de service qui lui sont assignés. Les Domain Admins sont également des groupes globaux au lieu de locaux de domaine. Plus d'informations sur l'appartenance aux groupes peuvent être trouvées plus tard dans ce module.

Soyez prudent quant à qui, le cas échéant, vous donnez accès à ces groupes. Un attaquant pourrait facilement obtenir les clés de l'entreprise s'il obtient l'accès à un utilisateur assigné à ces groupes.

**Appartenance au groupe Domain Admins :**

```powershell
PS C:\htb> Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members

DistinguishedName : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Name              : Domain Admins
Members           : {CN=htb-student_adm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL, CN=sharepoint
                    admin,CN=Users,DC=INLANEFREIGHT,DC=LOCAL, CN=FREIGHTLOGISTICSUSER,OU=Service
                    Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=PROXYAGENT,OU=Service
                    Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
```

***

### <mark style="color:blue;">Attribution des Droits Utilisateur</mark>

En fonction de leur appartenance actuelle aux groupes et d'autres facteurs tels que les privilèges que les administrateurs peuvent assigner via la stratégie de groupe (GPO), les utilisateurs peuvent avoir divers droits assignés à leur compte.

Cet article Microsoft sur l'attribution des droits utilisateur fournit une explication détaillée de chacun des droits utilisateur qui peuvent être définis dans Windows. Tous les droits listés ici ne sont pas importants pour nous d'un point de vue sécurité en tant que testeurs d'intrusion ou défenseurs, mais certains droits accordés à un compte peuvent conduire à des conséquences non intentionnelles telles que l'escalade de privilèges ou l'accès à des fichiers sensibles.

Par exemple, disons que nous pouvons obtenir un accès en écriture sur un objet de stratégie de groupe (GPO) appliqué à une OU contenant un ou plusieurs utilisateurs que nous contrôlons. Dans cet exemple, nous pourrions potentiellement exploiter un outil tel que SharpGPOAbuse pour assigner des droits ciblés à un utilisateur. Nous pouvons effectuer de nombreuses actions dans le domaine pour faire progresser notre accès avec ces nouveaux droits.

#### <mark style="color:green;">Exemples de Privilèges Importants</mark>

**SeRemoteInteractiveLogonRight** Ce privilège pourrait donner à notre utilisateur cible le droit de se connecter à un hôte via Remote Desktop (RDP), ce qui pourrait potentiellement être utilisé pour obtenir des données sensibles ou escalader les privilèges.

**SeBackupPrivilege** Cela accorde à un utilisateur la capacité de créer des sauvegardes système et pourrait être utilisé pour obtenir des copies de fichiers système sensibles qui peuvent être utilisés pour récupérer des mots de passe tels que les ruches de registre SAM et SYSTEM et le fichier de base de données Active Directory NTDS.dit.

**SeDebugPrivilege** Cela permet à un utilisateur de déboguer et d'ajuster la mémoire d'un processus. Avec ce privilège, les attaquants pourraient utiliser un outil tel que Mimikatz pour lire l'espace mémoire du processus Local System Authority (LSASS) et obtenir toutes les informations d'identification stockées en mémoire.

**SeImpersonatePrivilege** Ce privilège nous permet d'usurper l'identité d'un jeton d'un compte privilégié tel que NT AUTHORITY\SYSTEM. Cela pourrait être exploité avec un outil tel que JuicyPotato, RogueWinRM, PrintSpoofer, etc., pour escalader les privilèges sur un système cible.

**SeLoadDriverPrivilege** Un utilisateur avec ce privilège peut charger et décharger des pilotes de périphérique qui pourraient potentiellement être utilisés pour escalader les privilèges ou compromettre un système.

**SeTakeOwnershipPrivilege** Cela permet à un processus de prendre possession d'un objet. À son niveau le plus basique, nous pourrions utiliser ce privilège pour accéder à un partage de fichiers ou à un fichier sur un partage qui nous était autrement inaccessible.

Il existe de nombreuses techniques disponibles pour abuser des droits utilisateur détaillées ici et ici. Bien qu'en dehors de la portée de ce module, il est essentiel de comprendre l'impact que l'attribution du mauvais privilège à un compte peut avoir au sein d'Active Directory. Une petite erreur d'administration peut conduire à une compromission complète du système ou de l'entreprise.

***

### <mark style="color:blue;">Visualisation des Privilèges d'un Utilisateur</mark>

Après s'être connecté à un hôte, taper la commande `whoami /priv` nous donnera une liste de tous les droits utilisateur assignés à l'utilisateur actuel. Certains droits ne sont disponibles qu'aux utilisateurs administratifs et ne peuvent être listés/exploités que lors de l'exécution d'une session CMD ou PowerShell élevée.

Ces concepts de droits élevés et de contrôle de compte d'utilisateur (UAC) sont des fonctionnalités de sécurité introduites avec Windows Vista qui limitent par défaut les applications à s'exécuter avec des permissions complètes sauf si cela est absolument nécessaire.

Si nous comparons et contrastons les droits disponibles en tant qu'admin dans une console non élevée vs. une console élevée, nous verrons qu'ils diffèrent radicalement. Examinons d'abord les droits disponibles pour un utilisateur Active Directory standard.

#### <mark style="color:blue;">Droits d'un Utilisateur de Domaine Standard</mark>

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Nous pouvons voir que les droits sont très limités, et aucun des droits "dangereux" décrits ci-dessus n'est présent. Ensuite, examinons un utilisateur privilégié. Ci-dessous sont les droits disponibles pour un utilisateur Domain Admin.

***

#### <mark style="color:blue;">Droits Domain Admin Non Élevés</mark>

Nous pouvons voir ce qui suit dans une console non élevée qui ne semble pas être plus que ce qui est disponible pour l'utilisateur de domaine standard. C'est parce que, par défaut, les systèmes Windows n'activent pas tous les droits à moins que nous n'exécutions la console CMD ou PowerShell dans un contexte élevé. Ceci est pour empêcher chaque application de s'exécuter avec les privilèges les plus élevés possibles. Ceci est contrôlé par quelque chose appelé User Account Control (UAC) qui est couvert en profondeur dans le module Windows Privilege Escalation.

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

#### Droits Domain Admin Élevés

Si nous entrons la même commande depuis une console PowerShell élevée, nous pouvons voir la liste complète des droits disponibles pour nous :

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

Les droits utilisateur augmentent en fonction des groupes dans lesquels ils sont placés ou de leurs privilèges assignés. Ci-dessous est un exemple des droits accordés à un membre du groupe Backup Operators.

Les utilisateurs de ce groupe ont d'autres droits actuellement restreints par UAC (des droits supplémentaires tels que le puissant SeBackupPrivilege ne sont pas activés par défaut dans une session de console standard). Néanmoins, nous pouvons voir à partir de cette commande qu'ils ont le SeShutdownPrivilege, ce qui signifie qu'ils peuvent éteindre un contrôleur de domaine.

Ce privilège à lui seul ne pourrait pas être utilisé pour accéder à des données sensibles mais pourrait causer une interruption de service massive s'ils se connectent localement à un contrôleur de domaine (pas à distance via RDP ou WinRM).

#### Droits des Backup Operators

```powershell
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
