# Windows User Privileges

***

{% hint style="warning" %}
Les **privilèges** dans Windows sont des **droits** qu’un compte peut se voir **accorder** pour effectuer une variété d'opérations sur le système local, comme **gérer les services**, **charger des pilotes**, **éteindre le système**, **déboguer une application**, etc.\
Les privilèges sont **différents** des **droits d'accès** (« access rights »), que le système utilise pour **autoriser ou refuser** l'accès aux objets sécurisables.

Les **privilèges des utilisateurs et des groupes** sont **stockés** dans une **base de données** et **attribués via un jeton d'accès** (access token) lorsqu’un utilisateur se connecte au système.\
Un compte peut avoir des privilèges **locaux** sur un ordinateur spécifique et des privilèges **différents sur d’autres systèmes**, s’il appartient à un domaine Active Directory.

Chaque fois qu’un utilisateur tente d’effectuer une **action privilégiée**, le système examine le **jeton d’accès** de l’utilisateur pour voir si le compte a les **privilèges nécessaires**, et s’ils sont **activés**.\
La plupart des privilèges sont **désactivés par défaut**. Certains peuvent être activés en ouvrant une **console cmd.exe ou PowerShell en tant qu’administrateur**, tandis que d'autres doivent être activés **manuellement**.
{% endhint %}

***

### <mark style="color:red;">Windows Authorization Process</mark>

Un **principal de sécurité** (security principal) est **tout ce que Windows peut authentifier** :

* comptes utilisateurs,
* comptes ordinateurs,
* processus fonctionnant avec le contexte de sécurité d’un utilisateur,
* ou **groupes de sécurité**.

Chaque principal de sécurité est identifié par un **SID (Security Identifier)** unique.

Quand un principal est créé, il reçoit un **SID permanent**.\
Lorsqu’un utilisateur tente d’accéder à un objet **sécurisable** (comme un dossier partagé), le système compare le **jeton d’accès** de l’utilisateur (SID utilisateur, SID des groupes, liste de privilèges, etc.) avec les **entrées de contrôle d’accès (ACEs)** dans le **descripteur de sécurité** de l’objet.

Ce descripteur contient :

* SID du propriétaire,
* SID du groupe,
* SACL (audit),
* DACL (droits d’accès),
* ACEs (droits pour utilisateurs/groupes).

Quand cette comparaison est terminée, le système **autorise ou refuse l’accès**.\
Ce processus se déroule **instantanément** à chaque fois qu’un utilisateur tente d’accéder à une ressource Windows.

<figure><img src="../../../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

[Image source](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals)

***

### <mark style="color:red;">Rights and Privileges in Windows</mark>

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Group</strong></td><td><strong>Description</strong></td></tr><tr><td>Default Administrators</td><td>Domain Admins and Enterprise Admins are "super" groups.</td></tr><tr><td>Server Operators</td><td>Members can modify services, access SMB shares, and backup files.</td></tr><tr><td>Backup Operators</td><td>Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.</td></tr><tr><td>Print Operators</td><td>Members can log on to DCs locally and "trick" Windows into loading a malicious driver.</td></tr><tr><td>Hyper-V Administrators</td><td>If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.</td></tr><tr><td>Account Operators</td><td>Members can modify non-protected accounts and groups in the domain.</td></tr><tr><td>Remote Desktop Users</td><td>Members are not given any useful permissions by default but are often granted additional rights such as <code>Allow Login Through Remote Desktop Services</code> and can move laterally using the RDP protocol.</td></tr><tr><td>Remote Management Users</td><td>Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).</td></tr><tr><td>Group Policy Creator Owners</td><td>Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.</td></tr><tr><td>Schema Admins</td><td>Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.</td></tr><tr><td>DNS Admins</td><td>Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to <a href="https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/">create a WPAD record</a>.</td></tr></tbody></table>

***

### <mark style="color:red;">User Rights Assignment</mark>

Ce sont des **droits système** que tu peux configurer par :

* **Stratégie locale** (`secpol.msc`)
* **Stratégie de groupe (GPO)** (`gpedit.msc`, ou via AD)
* **Appartenance à un groupe**

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th><th></th><th></th></tr></thead><tbody><tr><td>Setting <a href="https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants">Constant</a></td><td>Setting Name</td><td>Standard Assignment</td><td>Description</td></tr><tr><td>SeNetworkLogonRight</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network">Access this computer from the network</a></td><td>Administrators, Authenticated Users</td><td>Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.</td></tr><tr><td>SeRemoteInteractiveLogonRight</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services">Allow log on through Remote Desktop Services</a></td><td>Administrators, Remote Desktop Users</td><td>This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server.</td></tr><tr><td>SeBackupPrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories">Back up files and directories</a></td><td>Administrators</td><td>This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.</td></tr><tr><td>SeSecurityPrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log">Manage auditing and security log</a></td><td>Administrators</td><td>This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer.</td></tr><tr><td>SeTakeOwnershipPrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects">Take ownership of files or other objects</a></td><td>Administrators</td><td>This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.</td></tr><tr><td>SeDebugPrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs">Debug programs</a></td><td>Administrators</td><td>This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components.</td></tr><tr><td>SeImpersonatePrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication">Impersonate a client after authentication</a></td><td>Administrators, Local Service, Network Service, Service</td><td>This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.</td></tr><tr><td>SeLoadDriverPrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers">Load and unload device drivers</a></td><td>Administrators</td><td>This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code.</td></tr><tr><td>SeRestorePrivilege</td><td><a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories">Restore files and directories</a></td><td>Administrators</td><td>This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object.</td></tr></tbody></table>

{% hint style="warning" %}
Further information can be found [here](https://4sysops.com/archives/user-rights-assignment-in-windows-server-2016/).

[https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)
{% endhint %}

<mark style="color:green;">**Local Admin User Rights - Elevated**</mark>

```powershell-session
PS C:\htb> whoami 

------------------------

PS C:\htb> whoami /priv
```

⚠️ Quand un privilège est **"Disabled"**, cela signifie qu’il est **présent dans le jeton**, mais **non activé**.\
Il ne peut pas être utilisé tant qu’il n’est pas **activé manuellement** via un script ou un outil.

{% hint style="danger" %}
We will see ways to abuse various privileges throughout this module and various ways to enable specific privileges within our current process. One example is this PowerShell [script](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts/Enable-Privilege.ps1) which can be used to enable certain privileges, or this [script](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) which can be used to adjust token privileges.
{% endhint %}

***

### <mark style="color:red;">Detection</mark>

{% hint style="warning" %}
This [post](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) is worth a read for more information on Windows privileges as well as detecting and preventing abuse, specifically by logging event [4672: Special privileges assigned to new logon](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672) which will generate an event if certain sensitive privileges are assigned to a new logon session. This can be fine-tuned in many ways, such as by monitoring privileges that should _never_ be assigned or those that should only ever be assigned to specific accounts.
{% endhint %}
