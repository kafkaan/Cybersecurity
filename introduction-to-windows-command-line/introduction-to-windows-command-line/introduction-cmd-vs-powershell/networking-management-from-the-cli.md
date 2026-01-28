# Networking Management from The CLI

## <mark style="color:red;">Gestion Réseau depuis la Ligne de Commande</mark>

### <mark style="color:blue;">Qu'est-ce que le Réseau au sein d'un Réseau Windows ?</mark>

Là où les choses diffèrent un peu, c'est dans la façon dont les hôtes Windows communiquent entre eux, avec les domaines et avec d'autres hôtes Linux. Ci-dessous, nous couvrirons rapidement quelques protocoles standard que vous pourriez rencontrer lors de l'administration ou des tests d'intrusion sur des hôtes Windows.

#### <mark style="color:green;">Protocoles Windows Courants</mark>

<table data-full-width="true"><thead><tr><th>Protocole</th><th>Description</th></tr></thead><tbody><tr><td><strong>SMB</strong></td><td>SMB fournit aux hôtes Windows la capacité de partager des ressources, des fichiers et un moyen standard d'authentification entre hôtes pour déterminer si l'accès aux ressources est autorisé. Pour les autres distributions, SAMBA est l'option open-source.</td></tr><tr><td><strong>NetBIOS</strong></td><td>NetBIOS lui-même n'est pas directement un service ou un protocole mais un mécanisme de connexion et de conversation largement utilisé dans les réseaux. C'était le mécanisme de transport original pour SMB, mais cela a depuis changé. Maintenant, il sert de mécanisme d'identification alternatif lorsque DNS échoue. Peut également être connu sous le nom de NBT-NS (service de noms NetBIOS).</td></tr><tr><td><strong>LDAP</strong></td><td>LDAP est un protocole open-source multiplateforme utilisé pour l'authentification et l'autorisation avec divers services d'annuaire. C'est ainsi que de nombreux appareils différents dans les réseaux modernes peuvent communiquer avec des services de structure d'annuaire importants tels qu'Active Directory.</td></tr><tr><td><strong>LLMNR</strong></td><td>LLMNR fournit un service de résolution de noms basé sur DNS et fonctionne si DNS n'est pas disponible ou ne fonctionne pas. Ce protocole est un protocole multicast et, en tant que tel, fonctionne uniquement sur les liens locaux (dans un domaine de diffusion normal, pas à travers les liens de couche trois).</td></tr><tr><td><strong>DNS</strong></td><td>DNS est une norme de nommage commune utilisée sur Internet et dans la plupart des types de réseaux modernes. DNS nous permet de référencer des hôtes par un nom unique au lieu de leur adresse IP. C'est ainsi que nous pouvons référencer un site Web par "WWW.google.com" au lieu de "8.8.8.8". En interne, c'est ainsi que nous demandons des ressources et un accès à partir d'un réseau.</td></tr><tr><td><strong>HTTP/HTTPS</strong></td><td>HTTP et HTTPS sont les moyens non sécurisé et sécurisé de demander et d'utiliser des ressources sur Internet. Ces protocoles sont utilisés pour accéder et utiliser des ressources telles que des serveurs Web, envoyer et recevoir des données de sources distantes, et bien plus encore.</td></tr><tr><td><strong>Kerberos</strong></td><td>Kerberos est un protocole d'authentification au niveau réseau. Dans les temps modernes, nous sommes plus susceptibles de le voir lors de l'authentification Active Directory lorsque les clients demandent des tickets pour l'autorisation d'utiliser les ressources du domaine.</td></tr><tr><td><strong>WinRM</strong></td><td>WinRM est une implémentation du protocole WS-Management. Il peut être utilisé pour gérer les fonctionnalités matérielles et logicielles des hôtes. Il est principalement utilisé dans l'administration informatique mais peut également être utilisé pour l'énumération d'hôtes et comme moteur de script.</td></tr><tr><td><strong>RDP</strong></td><td>RDP est une implémentation Windows d'un protocole de services d'interface utilisateur réseau qui fournit aux utilisateurs une interface graphique pour accéder aux hôtes via une connexion réseau. Cela permet une utilisation complète de l'interface utilisateur, y compris le passage des entrées clavier et souris à l'hôte distant.</td></tr><tr><td><strong>SSH</strong></td><td>SSH est un protocole sécurisé qui peut être utilisé pour l'accès sécurisé aux hôtes, le transfert de fichiers et la communication générale entre hôtes réseau. Il fournit un moyen d'accéder en toute sécurité aux hôtes et services sur des réseaux non sécurisés.</td></tr></tbody></table>

***

### <mark style="color:blue;">Accès Local vs Accès Distant</mark>

#### <mark style="color:green;">Accès Local</mark>

L'accès à l'hôte local se produit lorsque nous sommes directement au terminal en utilisant ses ressources, comme vous l'êtes actuellement depuis votre PC. Habituellement, cela ne nécessitera pas l'utilisation de protocoles d'accès spécifiques, sauf lorsque nous demandons des ressources à des hôtes en réseau ou tentons d'accéder à Internet. Ci-dessous, nous présenterons quelques cmdlets et autres moyens de vérifier et valider les paramètres réseau sur nos hôtes.

#### <mark style="color:green;">Interrogation des Paramètres Réseau</mark>

Avant de faire quoi que ce soit d'autre, validons les paramètres réseau sur l'hôte de M. Tanaka. Nous commencerons par exécuter la commande IPConfig. Ce n'est pas une commande native de PowerShell, mais elle est compatible.

**IPConfig**

```powershell
PS C:\htb> ipconfig 

Configuration IP de Windows

Carte Ethernet Ethernet0:

   Suffixe DNS propre à la connexion. . : .htb
   Adresse IPv6 de liaison locale. . . : fe80::c5ca:594d:759d:e0c1%11
   Adresse IPv4. . . . . . . . . . . . : 10.129.203.105
   Masque de sous-réseau. . . . . . . . : 255.255.0.0
   Passerelle par défaut. . . . . . . . : fe80::250:56ff:feb9:b9fc%11
                                         10.129.0.1
```

Comme nous pouvons le voir, ipconfig nous montrera les paramètres de base de notre interface réseau. Nous avons en sortie les adresses IPv4/6, notre passerelle, les masques de sous-réseau et le suffixe DNS si un est défini. Nous pouvons afficher les paramètres réseau complets en ajoutant le modificateur `/all` à la commande ipconfig comme suit :

```powershell
PS C:\htb> ipconfig /all 

Configuration IP de Windows

   Nom de l'hôte . . . . . . . . . . . : ICL-WIN11
   Suffixe DNS principal . . . . . . . : greenhorn.corp
   Type de nœud. . . . . . . . . . . . : Hybride
   Routage IP activé . . . . . . . . . : Non
   Proxy WINS activé . . . . . . . . . : Non
   Liste de recherche de suffixes DNS. : greenhorn.corp
                                         htb

Carte Ethernet Ethernet0:

   Suffixe DNS propre à la connexion. . : .htb
   Description . . . . . . . . . . . . : Carte Ethernet vmxnet3
   Adresse physique. . . . . . . . . . : 00-50-56-B9-4F-CB
   DHCP activé . . . . . . . . . . . . : Oui
   Configuration automatique activée . : Oui
   Adresse IPv6. . . . . . . . . . . . : dead:beef::222(Préféré)
   Bail obtenu. . . . . . . . . . . . . : lundi 17 octobre 2022 9:40:14
   Le bail expire . . . . . . . . . . . : mardi 25 octobre 2022 9:59:17
   <SNIP>
   Adresse IPv4. . . . . . . . . . . . : 10.129.203.105(Préféré)
   Masque de sous-réseau . . . . . . . : 255.255.0.0
   Bail obtenu. . . . . . . . . . . . . : lundi 17 octobre 2022 9:40:13
   Le bail expire . . . . . . . . . . . : mardi 25 octobre 2022 10:10:16
   Passerelle par défaut . . . . . . . : fe80::250:56ff:feb9:b9fc%11
                                         10.129.0.1
   Serveur DHCP . . . . . . . . . . . . : 10.129.0.1
   DHCPv6 IAID . . . . . . . . . . . . : 335564886
   DUID client DHCPv6. . . . . . . . . : 00-01-00-01-2A-3D-00-D6-00-50-56-B9-4F-CB
   Serveurs DNS. . . . . . . . . . . . : 1.1.1.1
                                         8.8.8.8
   NetBIOS sur Tcpip . . . . . . . . . : Activé
   Liste de recherche de suffixes DNS propres à la connexion :
                                         htb

Carte Ethernet Ethernet2:

   Suffixe DNS propre à la connexion. . :
   Description . . . . . . . . . . . . : Carte Ethernet vmxnet3 #2
   Adresse physique. . . . . . . . . . : 00-50-56-B9-F5-7E
   DHCP activé . . . . . . . . . . . . : Non
   Configuration automatique activée . : Oui
   Adresse IPv6 de liaison locale. . . : fe80::d1fb:79d5:6d0b:41de%14(Préféré)
   Adresse IPv4. . . . . . . . . . . . : 172.16.5.100(Préféré)
   Masque de sous-réseau . . . . . . . : 255.255.255.0
   Passerelle par défaut . . . . . . . : 172.16.5.1
   DHCPv6 IAID . . . . . . . . . . . . : 318787670
   DUID client DHCPv6. . . . . . . . . : 00-01-00-01-2A-3D-00-D6-00-50-56-B9-4F-CB
   Serveurs DNS. . . . . . . . . . . . : 172.16.5.155
   NetBIOS sur Tcpip . . . . . . . . . : Activé
```

<mark style="color:$success;">**ARP**</mark>

Examinons les paramètres ARP et voyons si son hôte a communiqué avec d'autres sur le réseau. Pour rappel, ARP est un protocole utilisé pour traduire les adresses IP en adresses physiques. L'adresse physique est utilisée aux niveaux inférieurs des modèles OSI/TCP-IP pour la communication. Pour qu'il affiche les entrées ARP actuelles de l'hôte, nous utiliserons le commutateur `-a`.

```powershell
PS C:\htb> arp -a

Interface: 10.129.203.105 --- 0xb
  Adresse Internet      Adresse physique      Type
  10.129.0.1            00-50-56-b9-b9-fc     dynamique
  10.129.204.58         00-50-56-b9-5f-41     dynamique
  10.129.255.255        ff-ff-ff-ff-ff-ff     statique
  224.0.0.22            01-00-5e-00-00-16     statique
  224.0.0.251           01-00-5e-00-00-fb     statique
  224.0.0.252           01-00-5e-00-00-fc     statique
  239.255.255.250       01-00-5e-7f-ff-fa     statique
  255.255.255.255       ff-ff-ff-ff-ff-ff     statique

Interface: 172.16.5.100 --- 0xe
  Adresse Internet      Adresse physique      Type
  172.16.5.155          00-50-56-b9-e2-30     dynamique
  172.16.5.255          ff-ff-ff-ff-ff-ff     statique
  224.0.0.22            01-00-5e-00-00-16     statique
  224.0.0.251           01-00-5e-00-00-fb     statique
  224.0.0.252           01-00-5e-00-00-fc     statique
  239.255.255.250       01-00-5e-7f-ff-fa     statique
```

La sortie de `arp -a` est assez simple. Nous recevons des entrées de nos adaptateurs réseau concernant les hôtes dont il est au courant ou avec lesquels il a récemment communiqué. Sans surprise, puisque cet hôte est assez nouveau, il n'a pas encore communiqué avec trop d'hôtes. Juste les passerelles, notre hôte distant et l'hôte 172.16.5.155, le contrôleur de domaine pour Greenhorn.corp. Rien de fou à voir ici.

***

<mark style="color:$success;">**Nslookup**</mark>

Maintenant, validons que notre configuration DNS fonctionne correctement. Nous utiliserons nslookup, un outil intégré d'interrogation DNS, pour tenter de résoudre l'adresse IP / le nom DNS du contrôleur de domaine Greenhorn.

```powershell
PS C:\htb> nslookup ACADEMY-ICL-DC

La demande DNS a expiré.
    le délai d'expiration était de 2 secondes.
Serveur :  Inconnu
Adresse :  172.16.5.155

Nom :    ACADEMY-ICL-DC.greenhorn.corp
Adresse :  172.16.5.155
```

<mark style="color:$success;">**Netstat**</mark>

Maintenant que nous avons validé les paramètres DNS de M. Tanaka, vérifions les ports ouverts sur l'hôte. Nous pouvons le faire en utilisant `netstat -an`. Netstat affichera les connexions réseau actuelles à notre hôte. Le commutateur `-an` imprimera toutes les connexions et ports d'écoute et les placera sous forme numérique.

```powershell
PS C:\htb> netstat -an 

Connexions actives

  Proto  Adresse locale          Adresse distante        État
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING
  TCP    10.129.203.105:22      10.10.14.19:32557      ESTABLISHED
  TCP    172.16.5.100:139       0.0.0.0:0              LISTENING
  TCP    [::]:22                [::]:0                 LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::]:3389              [::]:0                 LISTENING
  TCP    [::]:5985              [::]:0                 LISTENING
  TCP    [::]:47001             [::]:0                 LISTENING
  UDP    0.0.0.0:123            *:*
<SNIP>
  UDP    172.16.5.100:137       *:*
  UDP    172.16.5.100:138       *:*
  UDP    172.16.5.100:1900      *:*
  UDP    172.16.5.100:54453     *:*
```

***

### <mark style="color:blue;">Cmdlets Réseau PowerShell</mark>

PowerShell possède plusieurs cmdlets intégrés puissants conçus pour gérer les services réseau et l'administration. Les modules NetAdapter, NetConnection et NetTCPIP ne sont que quelques-uns avec lesquels nous allons pratiquer aujourd'hui.

#### <mark style="color:green;">Tableau des Cmdlets Réseau</mark>

<table data-full-width="true"><thead><tr><th>Cmdlet</th><th>Description</th></tr></thead><tbody><tr><td><strong>Get-NetIPInterface</strong></td><td>Récupérer toutes les propriétés d'adaptateur réseau visibles.</td></tr><tr><td><strong>Get-NetIPAddress</strong></td><td>Récupère les configurations IP de chaque adaptateur. Similaire à IPConfig.</td></tr><tr><td><strong>Get-NetNeighbor</strong></td><td>Récupère les entrées voisines du cache. Similaire à arp -a.</td></tr><tr><td><strong>Get-Netroute</strong></td><td>Imprimera la table de routage actuelle. Similaire à IPRoute.</td></tr><tr><td><strong>Set-NetAdapter</strong></td><td>Définit les propriétés de base de l'adaptateur au niveau de la couche 2 telles que l'ID VLAN, la description et l'adresse MAC.</td></tr><tr><td><strong>Set-NetIPInterface</strong></td><td>Modifie les paramètres d'une interface, y compris l'état DHCP, MTU et autres métriques.</td></tr><tr><td><strong>New-NetIPAddress</strong></td><td>Crée et configure une adresse IP.</td></tr><tr><td><strong>Set-NetIPAddress</strong></td><td>Modifie la configuration d'un adaptateur réseau.</td></tr><tr><td><strong>Disable-NetAdapter</strong></td><td>Utilisé pour désactiver les interfaces d'adaptateur réseau.</td></tr><tr><td><strong>Enable-NetAdapter</strong></td><td>Utilisé pour réactiver les adaptateurs réseau et autoriser les connexions réseau.</td></tr><tr><td><strong>Restart-NetAdapter</strong></td><td>Utilisé pour redémarrer un adaptateur. Peut être utile pour aider à pousser les modifications apportées aux paramètres de l'adaptateur.</td></tr><tr><td><strong>Test-NetConnection</strong></td><td>Permet d'exécuter des vérifications de diagnostic sur une connexion. Prend en charge ping, tcp, traçage de route, et plus encore.</td></tr></tbody></table>

Nous n'allons pas montrer chaque cmdlet en utilisation, mais il serait prudent de fournir une référence rapide pour votre utilisation. Tout d'abord, nous commencerons avec Get-NetIPInterface.

#### Get-NetIPInterface

{% code fullWidth="true" %}
```powershell
PS C:\htb> Get-NetIPInterface

ifIndex InterfaceAlias                  AddressFamily NlMtu(Bytes) InterfaceMetric Dhcp     ConnectionState PolicyStore
------- --------------                  ------------- ------------ --------------- ----     --------------- -----------
20      Ethernet 3                      IPv6                  1500              25 Enabled  Disconnected    ActiveStore
14      VMware Network Adapter VMnet8   IPv6                  1500              35 Enabled  Connected       ActiveStore
8       VMware Network Adapter VMnet2   IPv6                  1500              35 Enabled  Connected       ActiveStore
10      VMware Network Adapter VMnet1   IPv6                  1500              35 Enabled  Connected       ActiveStore
17      Local Area Connection* 2        IPv6                  1500              25 Enabled  Disconnected    ActiveStore
21      Bluetooth Network Connection    IPv6                  1500              65 Disabled Disconnected    ActiveStore
15      Local Area Connection* 1        IPv6                  1500              25 Disabled Disconnected    ActiveStore
25      Wi-Fi                           IPv6                  1500              40 Enabled  Connected       ActiveStore
7       Local Area Connection           IPv6                  1500              25 Enabled  Disconnected    ActiveStore
1       Loopback Pseudo-Interface 1     IPv6            4294967295              75 Disabled Connected       ActiveStore
20      Ethernet 3                      IPv4                  1500              25 Enabled  Disconnected    ActiveStore
14      VMware Network Adapter VMnet8   IPv4                  1500              35 Disabled Connected       ActiveStore
8       VMware Network Adapter VMnet2   IPv4                  1500              35 Disabled Connected       ActiveStore
10      VMware Network Adapter VMnet1   IPv4                  1500              35 Disabled Connected       ActiveStore
17      Local Area Connection* 2        IPv4                  1500              25 Disabled Disconnected    ActiveStore
21      Bluetooth Network Connection    IPv4                  1500              65 Enabled  Disconnected    ActiveStore
15      Local Area Connection* 1        IPv4                  1500              25 Enabled  Disconnected    ActiveStore
25      Wi-Fi                           IPv4                  1500              40 Enabled  Connected       ActiveStore
7       Local Area Connection           IPv4                  1500               1 Disabled Disconnected    ActiveStore
1       Loopback Pseudo-Interface 1     IPv4            4294967295              75 Disabled Connected       ActiveStore
```
{% endcode %}

Cette liste nous montre nos interfaces disponibles sur l'hôte d'une manière un peu alambiquée. Nous recevons beaucoup de métriques, mais les adaptateurs sont répartis par AddressFamily. Nous voyons donc des entrées pour chaque adaptateur deux fois si IPv4 et IPv6 sont activés sur cette interface particulière. Les propriétés ifindex et InterfaceAlias sont particulièrement utiles. Ces propriétés facilitent notre utilisation des autres cmdlets fournis par le module NetTCPIP.

#### Get-NetIPAddress

Obtenons les informations de l'adaptateur pour notre connexion Wi-Fi à ifIndex 25 en utilisant le cmdlet Get-NetIPAddress.

```powershell
PS C:\htb> Get-NetIPAddress -ifIndex 25

IPAddress         : fe80::a0fc:2e3d:c92a:48df%25
InterfaceIndex    : 25
InterfaceAlias    : Wi-Fi
AddressFamily     : IPv6
Type              : Unicast
PrefixLength      : 64
PrefixOrigin      : WellKnown
SuffixOrigin      : Link
AddressState      : Preferred
ValidLifetime     : Infinite ([TimeSpan]::MaxValue)
PreferredLifetime : Infinite ([TimeSpan]::MaxValue)
SkipAsSource      : False
PolicyStore       : ActiveStore

IPAddress         : 192.168.86.211
InterfaceIndex    : 25
InterfaceAlias    : Wi-Fi
AddressFamily     : IPv4
Type              : Unicast
PrefixLength      : 24
PrefixOrigin      : Dhcp
SuffixOrigin      : Dhcp
AddressState      : Preferred
ValidLifetime     : 21:35:36
PreferredLifetime : 21:35:36
SkipAsSource      : False
PolicyStore       : ActiveStore
```

Ce cmdlet a également renvoyé pas mal d'informations. Remarquez comment nous avons utilisé le numéro ifIndex pour demander l'information ? Nous pouvons faire la même chose avec l'InterfaceAlias également. Ce cmdlet renvoie pas mal d'informations, telles que l'index, l'alias, l'état DHCP, le type d'interface et d'autres métriques. Cela reflète la plupart de ce que nous verrions si nous exécutions l'exécutable IPconfig depuis l'invite de commande.

#### Set-NetIPInterface et Set-NetIPAddress

Maintenant, que se passe-t-il si nous voulons modifier un paramètre sur l'interface ? Nous pouvons le faire avec les cmdlets Set-NetIPInterface et Set-NetIPAddress. Dans cet exemple, disons que nous voulons changer l'état DHCP de l'interface d'activé à désactivé, et changer l'IP d'une IP automatiquement attribuée par DHCP à une IP que nous choisissons et définissons manuellement. Nous accomplirions cela comme suit :

```powershell
PS C:\htb> Set-NetIPInterface -InterfaceIndex 25 -Dhcp Disabled
```

En désactivant la propriété DHCP avec le cmdlet Set-NetIPInterface, nous pouvons maintenant définir notre adresse IP manuelle. Nous le faisons avec le cmdlet Set-NetIPAddress.

```powershell
PS C:\htb> Set-NetIPAddress -InterfaceIndex 25 -IPAddress 10.10.100.54 -PrefixLength 24

PS C:\htb> Get-NetIPAddress -ifindex 20 | ft InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength

InterfaceIndex InterfaceAlias IPAddress                   PrefixLength
-------------- -------------- ---------                   ------------
            20 Ethernet 3     fe80::7408:bbf:954a:6ae5%20           64
            20 Ethernet 3     10.10.100.54                          24

PS C:\htb> Get-NetIPinterface -ifindex 20 | ft ifIndex,InterfaceAlias,Dhcp

ifIndex InterfaceAlias     Dhcp
------- --------------     ----
     20 Ethernet 3     Disabled
     20 Ethernet 3     Disabled
```

La commande ci-dessus définit maintenant notre adresse IP à 10.10.100.54 et le PrefixLength (également connu sous le nom de masque de sous-réseau) à 24. En regardant nos vérifications, nous pouvons voir que ces paramètres sont en place. Pour être en sécurité, redémarrons notre adaptateur réseau et testons notre connexion pour voir si cela persiste.

#### Restart-NetAdapter

```powershell
PS C:\htb> Restart-NetAdapter -Name 'Ethernet 3'
```

Tant que rien ne se passe mal, vous ne recevrez pas de sortie. Donc, en ce qui concerne Restart-NetAdapter, pas de nouvelles, bonnes nouvelles. Le moyen le plus simple de dire au cmdlet quelle interface redémarrer est avec la propriété Name, qui est la même que l'InterfaceAlias des commandes précédentes que nous avons exécutées.

#### Test-NetConnection

Maintenant, pour nous assurer que nous avons toujours une connexion, nous pouvons utiliser le cmdlet Test-NetConnection.

```powershell
PS C:\htb> Test-NetConnection

ComputerName           : <snip>msedge.net
RemoteAddress          : 13.107.4.52
InterfaceAlias         : Ethernet 3
SourceAddress          : 10.10.100.54
PingSucceeded          : True
PingReplyDetails (RTT) : 44 ms
```

Le Test-NetConnection est un cmdlet puissant, capable de tester au-delà de la connectivité réseau de base pour déterminer si nous pouvons atteindre un autre hôte. Il peut nous renseigner sur nos résultats TCP, des métriques détaillées, des diagnostics de route et plus encore. Il serait intéressant de consulter cet article de Microsoft sur Test-NetConnection.

Maintenant que nous avons terminé notre tâche et validé les paramètres réseau de M. Tanaka sur son hôte, discutons un peu de la connectivité d'accès à distance.

***

### <mark style="color:blue;">Accès Distant</mark>

Lorsque nous ne pouvons pas accéder aux systèmes Windows ou devons gérer des hôtes à distance, nous pouvons utiliser PowerShell, SSH et RDP, entre autres outils, pour effectuer notre travail. Couvrons les principales façons dont nous pouvons activer et utiliser l'accès distant. Tout d'abord, nous discuterons de SSH.

#### <mark style="color:$success;">Comment Activer l'Accès Distant ? (SSH, PSSessions, etc.)</mark>

**Activation de l'Accès SSH**

Nous pouvons utiliser SSH pour accéder à PowerShell sur un système Windows via le réseau. À partir de 2018, SSH via les applications client et serveur OpenSSH a été accessible et inclus dans toutes les versions de Windows Server et Client. Cela en fait un mécanisme de communication facile à utiliser et extensible pour notre usage administratif. La configuration d'OpenSSH sur nos hôtes est simple. Essayons. Nous devons installer le composant SSH Server et l'application cliente pour accéder à un hôte via SSH à distance.

**Configuration de SSH sur une Cible Windows**

Nous pouvons configurer un serveur SSH sur une cible Windows en utilisant le cmdlet Add-WindowsCapability et confirmer qu'il est installé avec succès en utilisant le cmdlet Get-WindowsCapability.

```powershell
PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : NotPresent

PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

Path          :
Online        : True
RestartNeeded : False

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : NotPresent

PS C:\Users\htb-student> Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

Path          :
Online        : True
RestartNeeded : False

PS C:\Users\htb-student> Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

Name  : OpenSSH.Client~~~~0.0.1.0
State : Installed

Name  : OpenSSH.Server~~~~0.0.1.0
State : Installed
```

**Démarrage du Service SSH et Configuration du Type de Démarrage**

Une fois que nous avons confirmé que SSH est installé, nous pouvons utiliser le cmdlet Start-Service pour démarrer le service SSH. Nous pouvons également utiliser le cmdlet Set-Service pour configurer les paramètres de démarrage du service SSH si nous le choisissons.

```powershell
PS C:\Users\htb-student> Start-Service sshd  
  
PS C:\Users\htb-student> Set-Service -Name sshd -StartupType 'Automatic'  
```

#### <mark style="color:$success;">Accès à PowerShell via SSH</mark>

Avec SSH installé et en cours d'exécution sur une cible Windows, nous pouvons nous connecter via le réseau avec un client SSH.

**Connexion depuis Windows**

```powershell
PS C:\Users\administrator> ssh htb-student@10.129.224.248

htb-student@10.129.224.248 password:
```

Par défaut, cela nous connectera à une session CMD, mais nous pouvons taper `powershell` pour entrer dans une session PowerShell, comme mentionné précédemment dans cette section.

```cmd
WS01\htb-student@WS01 C:\Users\htb-student> powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. Tous droits réservés. 

PS C:\Users\htb-student>
```

**Connexion depuis Linux**

Nous remarquerons que les étapes pour se connecter à une cible Windows via SSH en utilisant Linux sont identiques à celles lors de la connexion depuis Windows.

```bash
PS C:\Users\administrator> ssh htb-student@10.129.224.248

htb-student@10.129.224.248 password:

WS01\htb-student@WS01 C:\Users\htb-student> powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. Tous droits réservés. 

PS C:\Users\htb-student>
```

Maintenant que nous avons couvert SSH, passons du temps à couvrir l'activation et l'utilisation de WinRM pour l'accès et la gestion à distance.

***

### <mark style="color:blue;">Activation de WinRM</mark>

Windows Remote Management (WinRM) peut être configuré en utilisant des cmdlets PowerShell dédiés et nous pouvons entrer dans une session PowerShell interactive ainsi qu'émettre des commandes sur une ou plusieurs cibles Windows distantes. Nous remarquerons que WinRM est plus couramment activé sur les systèmes d'exploitation Windows Server, afin que les administrateurs informatiques puissent effectuer des tâches sur un ou plusieurs hôtes. Il est activé par défaut dans Windows Server.

En raison de la demande croissante de la capacité de gérer à distance et d'automatiser les tâches sur les systèmes Windows, nous verrons probablement WinRM activé sur de plus en plus de systèmes d'exploitation de bureau Windows (Windows 10 et Windows 11) également. Lorsque WinRM est activé sur une cible Windows, il écoute sur les ports logiques 5985 et 5986.

#### Activation et Configuration de WinRM

WinRM peut être activé sur une cible Windows en utilisant les commandes suivantes :

```powershell
PS C:\WINDOWS\system32> winrm quickconfig

Le service WinRM est déjà en cours d'exécution sur cette machine.
WinRM n'est pas configuré pour permettre l'accès distant à cette machine pour la gestion.
Les modifications suivantes doivent être apportées :

Activer l'exception pare-feu WinRM.
Configurer LocalAccountTokenFilterPolicy pour accorder des droits administratifs à distance aux utilisateurs locaux.

Effectuer ces modifications [o/n]? o

WinRM a été mis à jour pour la gestion à distance.

Exception de pare-feu WinRM activée.
LocalAccountTokenFilterPolicy configuré pour accorder des droits administratifs à distance aux utilisateurs locaux.
```

Tant que les informations d'identification pour accéder au système sont connues, toute personne pouvant atteindre la cible sur le réseau peut se connecter après l'exécution de cette commande. Les administrateurs informatiques devraient prendre des mesures supplémentaires pour renforcer ces configurations WinRM, en particulier si le système sera accessible à distance via Internet. Parmi certaines de ces options de renforcement figurent :

* Configurer TrustedHosts pour inclure uniquement les adresses IP/noms d'hôtes qui seront utilisés pour la gestion à distance
* Configurer HTTPS pour le transport
* Joindre les systèmes Windows à un environnement de domaine Active Directory et appliquer l'authentification Kerberos

#### <mark style="color:$success;">Test de l'Accès Distant PowerShell</mark>

Une fois que nous avons activé et configuré WinRM, nous pouvons tester l'accès distant en utilisant le cmdlet PowerShell Test-WSMan.

**Test de l'Accès Non Authentifié**

```powershell
PS C:\Users\administrator> Test-WSMan -ComputerName "10.129.224.248"

wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0
```

L'exécution de ce cmdlet envoie une demande qui vérifie si le service WinRM est en cours d'exécution. Gardez à l'esprit que ceci n'est pas authentifié, donc aucune information d'identification n'est utilisée, c'est pourquoi aucune version de système d'exploitation n'est détectée. Cela nous montre que le service WinRM est en cours d'exécution sur la cible.

**Test de l'Accès Authentifié**

```powershell
PS C:\Users\administrator> Test-WSMan -ComputerName "10.129.224.248" -Authentication Negotiate

wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 10.0.17763 SP: 0.0 Stack: 3.0
```

Nous pouvons exécuter la même commande avec l'option `-Authentication Negotiate` pour tester si WinRM est authentifié, et nous recevrons la version du système d'exploitation (10.0.11764).

#### <mark style="color:$success;">Sessions PowerShell Distantes</mark>

Nous avons également la possibilité d'utiliser le cmdlet Enter-PSSession pour établir une session PowerShell avec une cible Windows.

**Établissement d'une Session PowerShell**

```powershell
PS C:\Users\administrator> Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate

[10.129.5.129]: PS C:\Users\htb-student\Documents> $PSVersionTable 
  
Name                           Value
----                           -----
PSVersion                      5.1.17763.592
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.17763.592
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
```

<mark style="color:$success;">**Utilisation de Enter-PSSession depuis Linux**</mark>

Nous pouvons effectuer cette même action à partir d'un hôte d'attaque basé sur Linux avec PowerShell core installé (comme dans Pwnbox). Rappelez-vous que PowerShell n'est pas exclusif à Windows et fonctionnera sur d'autres systèmes d'exploitation maintenant.

```bash
mrroboteLiot_1@htb[/htb]$ [PS]> Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate

Demande d'informations d'identification PowerShell
Entrez vos informations d'identification.
Mot de passe pour l'utilisateur htb-student : ***************

[10.129.224.248]: PS C:\Users\htb-student\Documents> $PSVersionTable

Name                           Value                                           
----                           -----                                           
PSVersion                      5.1.19041.1                                     
PSEdition                      Desktop                                         
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}                         
BuildVersion                   10.0.19041.1                                    
CLRVersion                     4.0.30319.42000                                 
WSManStackVersion              3.0                                             
PSRemotingProtocolVersion      2.3                                             
SerializationVersion           1.1.0.1
```

