# Active Directory Groups

## <mark style="color:red;">Groupes Active Directory</mark>

Après les utilisateurs, les groupes sont un autre objet important dans Active Directory. Ils permettent de regrouper des utilisateurs similaires et d'assigner en masse des droits et des accès. Les groupes sont une autre cible clé pour les attaquants et les testeurs d'intrusion, car les droits qu'ils confèrent à leurs membres peuvent ne pas être immédiatement apparents mais peuvent accorder des privilèges excessifs (et même non intentionnels) qui peuvent être exploités s'ils ne sont pas configurés correctement.

Il existe de nombreux groupes intégrés dans Active Directory, et la plupart des organisations créent également leurs propres groupes pour définir des droits et privilèges, gérant ainsi davantage l'accès au sein du domaine. Le nombre de groupes dans un environnement AD peut augmenter rapidement et devenir ingérable, conduisant potentiellement à des accès non intentionnels s'ils ne sont pas contrôlés.

Il est essentiel de comprendre l'impact de l'utilisation de différents types de groupes et pour toute organisation d'auditer périodiquement quels groupes existent dans leur domaine, les privilèges que ces groupes accordent à leurs membres, et de vérifier les appartenances excessives au-delà de ce qui est nécessaire pour qu'un utilisateur effectue son travail quotidien. Maintenant, nous allons discuter des différents types de groupes qui existent et des portées qui peuvent leur être assignées.

***

### <mark style="color:blue;">Différence entre Groupes et Unités Organisationnelles (OU)</mark>

Une question qui revient souvent est la différence entre les groupes et les unités organisationnelles (OU). Comme discuté précédemment dans le module, les OU sont utiles pour regrouper les utilisateurs, les groupes et les ordinateurs afin de faciliter la gestion et le déploiement des paramètres de stratégie de groupe vers des objets spécifiques dans le domaine.

Les groupes sont principalement utilisés pour assigner des permissions d'accès aux ressources. Les OU peuvent également être utilisées pour déléguer des tâches administratives à un utilisateur, comme la réinitialisation de mots de passe ou le déverrouillage de comptes utilisateurs sans leur donner de droits d'administration supplémentaires qu'ils pourraient hériter par l'appartenance à un groupe.

### <mark style="color:blue;">Types de Groupes</mark>

En termes simples, les groupes sont utilisés pour placer les utilisateurs, les ordinateurs et les objets de contact dans des unités de gestion qui facilitent l'administration des permissions et l'attribution de ressources telles que les imprimantes et l'accès aux partages de fichiers.

Par exemple, si un administrateur doit assigner l'accès à un nouveau lecteur partagé à 50 membres d'un département, il serait long d'ajouter chaque compte utilisateur individuellement. Accorder des permissions de cette manière rendrait également plus difficile l'audit de qui a accès aux ressources et difficile le nettoyage/révocation des permissions.

Au lieu de cela, un administrateur système peut soit utiliser un groupe existant, soit créer un nouveau groupe et accorder à ce groupe spécifique des permissions sur la ressource. À partir de là, chaque utilisateur du groupe héritera des permissions en fonction de son appartenance au groupe. Si les permissions doivent être modifiées ou révoquées pour un ou plusieurs utilisateurs, ils pourraient simplement être retirés du groupe, laissant les autres utilisateurs non affectés et leurs permissions intactes.

Groups in Active Directory have two fundamental characteristics: `type` and `scope`. The `group type` defines the group's purpose, while the `group scope` shows how the group can be used within the domain or forest. When creating a new group, we must select a group type. There are two main types: `security` and `distribution` groups.

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

#### <mark style="color:green;">Caractéristiques fondamentales des groupes</mark>

Les groupes dans Active Directory ont deux caractéristiques fondamentales : **le type** et **la portée**.

* Le **type de groupe** définit l'objectif du groupe
* La **portée du groupe** montre comment le groupe peut être utilisé au sein du domaine ou de la forêt

Lors de la création d'un nouveau groupe, nous devons sélectionner un type de groupe. Il existe deux types principaux : les groupes de sécurité et les groupes de distribution.

### <mark style="color:blue;">Type et Portée des Groupes</mark>

#### <mark style="color:green;">Types de groupes</mark>

<mark style="color:orange;">**Groupes de sécurité**</mark>

Le type groupes de sécurité est principalement utilisé pour faciliter l'attribution de permissions et de droits à une collection d'utilisateurs au lieu d'un à la fois. Ils simplifient la gestion et réduisent la charge lorsqu'on assigne des permissions et des droits pour une ressource donnée.

Tous les utilisateurs ajoutés à un groupe de sécurité hériteront de toutes les permissions assignées au groupe, ce qui facilite le déplacement des utilisateurs dans et hors des groupes tout en laissant les permissions du groupe inchangées.

<mark style="color:orange;">**Groupes de distribution**</mark>

Le type groupes de distribution est utilisé par les applications de messagerie telles que Microsoft Exchange pour distribuer des messages aux membres du groupe. Ils fonctionnent comme des listes de diffusion et permettent l'ajout automatique d'emails dans le champ "À" lors de la création d'un email dans Microsoft Outlook. Ce type de groupe ne peut pas être utilisé pour assigner des permissions aux ressources dans un environnement de domaine.

***

#### <mark style="color:green;">Portées des groupes</mark>

Il existe trois portées de groupe différentes qui peuvent être assignées lors de la création d'un nouveau groupe :

1. Groupe local de domaine (Domain Local Group)
2. Groupe global (Global Group)
3. Groupe universel (Universal Group)

<mark style="color:orange;">**Groupe Local de Domaine**</mark>

Les groupes locaux de domaine ne peuvent être utilisés que pour gérer les permissions aux ressources du domaine dans le domaine où ils ont été créés. Les groupes locaux ne peuvent pas être utilisés dans d'autres domaines mais PEUVENT contenir des utilisateurs d'AUTRES domaines. Les groupes locaux peuvent être imbriqués dans (contenus dans) d'autres groupes locaux mais PAS dans des groupes globaux.

<mark style="color:orange;">**Groupe Global**</mark>

Les groupes globaux peuvent être utilisés pour accorder l'accès aux ressources dans un autre domaine. Un groupe global ne peut contenir que des comptes du domaine où il a été créé. Les groupes globaux peuvent être ajoutés à la fois à d'autres groupes globaux et à des groupes locaux.

<mark style="color:orange;">**Groupe Universel**</mark>

La portée du groupe universel peut être utilisée pour gérer les ressources distribuées à travers plusieurs domaines et peut se voir accorder des permissions à n'importe quel objet au sein de la même forêt. Ils sont disponibles pour tous les domaines au sein d'une organisation et peuvent contenir des utilisateurs de n'importe quel domaine.

Contrairement aux groupes locaux de domaine et globaux, les groupes universels sont stockés dans le catalogue global (GC), et l'ajout ou la suppression d'objets d'un groupe universel déclenche une réplication à l'échelle de la forêt.

Il est recommandé que les administrateurs maintiennent d'autres groupes (tels que des groupes globaux) en tant que membres de groupes universels, car l'appartenance de groupes globaux au sein de groupes universels est moins susceptible de changer que l'appartenance d'utilisateurs individuels dans les groupes globaux. La réplication n'est déclenchée qu'au niveau du domaine individuel lorsqu'un utilisateur est retiré d'un groupe global.

Si des utilisateurs et ordinateurs individuels (au lieu de groupes globaux) sont maintenus dans des groupes universels, cela déclenchera une réplication à l'échelle de la forêt à chaque fois qu'un changement est effectué. Cela peut créer beaucoup de charge réseau et un potentiel de problèmes.

#### <mark style="color:green;">Exemples de portée de groupe AD</mark>

Voici un exemple des groupes dans AD et leurs paramètres de portée. Veuillez prêter attention à certains des groupes critiques et leur portée (les administrateurs Enterprise et Schema comparés aux administrateurs de domaine, par exemple).

```powershell
PS C:\htb> Get-ADGroup -Filter * | select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Print Operators                         DomainLocal
Backup Operators                        DomainLocal
Replicator                              DomainLocal
Remote Desktop Users                    DomainLocal
Network Configuration Operators         DomainLocal
Distributed COM Users                   DomainLocal
IIS_IUSRS                               DomainLocal
Cryptographic Operators                 DomainLocal
Event Log Readers                       DomainLocal
Certificate Service DCOM Access         DomainLocal
RDS Remote Access Servers               DomainLocal
RDS Endpoint Servers                    DomainLocal
RDS Management Servers                  DomainLocal
Hyper-V Administrators                  DomainLocal
Access Control Assistance Operators     DomainLocal
Remote Management Users                 DomainLocal
Storage Replica Administrators          DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Cert Publishers                         DomainLocal
Domain Admins                                Global
Domain Users                                 Global
Domain Guests                                Global
```

#### <mark style="color:green;">Changement de portée de groupe</mark>

Les portées de groupe peuvent être modifiées, mais il y a quelques restrictions :

* Un groupe global ne peut être converti en groupe universel que s'il ne fait PAS partie d'un autre groupe global
* Un groupe local de domaine ne peut être converti en groupe universel que si le groupe local de domaine ne contient PAS d'autres groupes locaux de domaine en tant que membres
* Un groupe universel peut être converti en groupe local de domaine sans aucune restriction
* Un groupe universel ne peut être converti en groupe global que s'il ne contient PAS d'autres groupes universels en tant que membres

***

### <mark style="color:blue;">Groupes Intégrés vs Groupes Personnalisés</mark>

Plusieurs groupes de sécurité intégrés sont créés avec une portée de groupe local de domaine lorsqu'un domaine est créé. Ces groupes sont utilisés à des fins administratives spécifiques et sont discutés davantage dans la section suivante.

Il est important de noter que seuls les comptes utilisateurs peuvent être ajoutés à ces groupes intégrés car ils ne permettent pas l'imbrication de groupes (groupes dans des groupes). Quelques exemples de groupes intégrés incluent Domain Admins, qui est un groupe de sécurité global et ne peut contenir que des comptes de son propre domaine.

Si une organisation souhaite permettre à un compte du domaine B d'effectuer des fonctions administratives sur un contrôleur de domaine dans le domaine A, le compte devrait être ajouté au groupe Administrators intégré, qui est un groupe local de domaine.

Bien qu'Active Directory soit prérempli avec de nombreux groupes, il est courant pour la plupart des organisations de créer des groupes supplémentaires (à la fois de sécurité et de distribution) pour leurs propres besoins. Les changements/ajouts à un environnement AD peuvent également déclencher la création de groupes supplémentaires.

Par exemple, lorsque Microsoft Exchange est ajouté à un domaine, il ajoute divers groupes de sécurité différents au domaine, dont certains sont hautement privilégiés et, s'ils ne sont pas gérés correctement, peuvent être utilisés pour obtenir un accès privilégié au sein du domaine.

***

### <mark style="color:blue;">Appartenance à un Groupe Imbriqué</mark>

L'appartenance à un groupe imbriqué est un concept important dans AD. Comme mentionné précédemment, un groupe local de domaine peut être membre d'un autre groupe local de domaine dans le même domaine.

Par cette appartenance, un utilisateur peut hériter de privilèges non assignés directement à son compte ou même au groupe dont il est directement membre, mais plutôt au groupe dont leur groupe est membre. Cela peut parfois conduire à des privilèges non intentionnels accordés à un utilisateur qui sont difficiles à découvrir sans une évaluation approfondie du domaine.

Des outils tels que BloodHound sont particulièrement utiles pour découvrir les privilèges qu'un utilisateur peut hériter à travers une ou plusieurs imbrications de groupes. C'est un outil clé pour les testeurs d'intrusion pour découvrir des mauvaises configurations nuancées et est également extrêmement puissant pour les administrateurs système et similaires pour obtenir des aperçus approfondis (visuellement) de la posture de sécurité de leur(s) domaine(s).

#### Exemple d'héritage via l'appartenance à un groupe imbriqué

Voici un exemple de privilèges hérités par l'appartenance à un groupe imbriqué. Bien que DCorner ne soit pas membre direct de Helpdesk Level 1, son appartenance à Help Desk lui accorde les mêmes privilèges que tout membre de Helpdesk Level 1 possède.

Dans ce cas, le privilège leur permettrait d'ajouter un membre au groupe Tier 1 Admins (GenericWrite). Si ce groupe confère des privilèges élevés dans le domaine, ce serait probablement une cible clé pour un testeur d'intrusion. Ici, nous pourrions ajouter notre utilisateur au groupe et obtenir les privilèges que les membres du groupe Tier 1 Admins reçoivent, tels que l'accès administrateur local à un ou plusieurs hôtes qui pourraient être utilisés pour un accès ultérieur.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Attributs Importants des Groupes</mark>

Comme les utilisateurs, les groupes ont de nombreux attributs. Certains des attributs de groupe les plus importants incluent :

* **cn** : Le cn ou Common-Name est le nom du groupe dans Active Directory Domain Services
* **member** : Quels objets utilisateur, groupe et contact sont membres du groupe
* **groupType** : Un entier qui spécifie le type et la portée du groupe
* **memberOf** : Une liste de tous les groupes qui contiennent le groupe en tant que membre (appartenance à un groupe imbriqué)
* **objectSid** : C'est l'identifiant de sécurité ou SID du groupe, qui est la valeur unique utilisée pour identifier le groupe en tant que principal de sécurité
