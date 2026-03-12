# User and Group Management

## [![](https://academy.hackthebox.com/images/logo.svg)](https://academy.hackthebox.com/dashboard)<mark style="color:red;">User and Group Management</mark>

***

### <mark style="color:blue;">What are User Accounts?</mark>

User accounts are a way for personnel to access and use a host's resources. In certain circumstances, the system will also utilize a specially provisioned user account to perform actions. When thinking about accounts, we typically run into four different types:

* Service Accounts
* Built-in accounts
* Local users
* Domain users

***

#### <mark style="color:blue;">Default Local User Accounts</mark>

Several accounts are created in every instance of Windows as the OS is installed to help with host management and basic usage. Below is a list of the standard built-in accounts.

**Built-In Accounts**

| **Account**           | **Description**                                                                                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Administrator`       | This account is used to accomplish administrative tasks on the local host.                                                                                       |
| `Default Account`     | The default account is used by the system for running multi-user auth apps like the Xbox utility.                                                                |
| `Guest Account`       | This account is a limited rights account that allows users without a normal user account to access the host. It is disabled by default and should stay that way. |
| `WDAGUtility Account` | This account is in place for the Defender Application Guard, which can sandbox application sessions.                                                             |

***

### <mark style="color:blue;">Brief Intro to Active Directory</mark>

> In a nutshell, `Active Directory` (AD) is a directory service for Windows environments that provides a central point of management for `users`, computers, `groups`, network devices, `file shares`, group policies, `devices`, and trusts with other organizations.&#x20;
>
> Think of it as the gatekeeper for an enterprise environment. Anyone who is a part of the domain can access resources freely, while anyone who is not is denied access to those same resources or, at a minimum, stuck waiting in the visitors center.

#### <mark style="color:green;">Local vs. Domain Joined Users</mark>

`How are they different?`

`Domain` users differ from `local` users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on user and group membership.&#x20;

Domain user accounts can log in to any host in the domain, while the local user only has permission to access the specific host they were created on.

***

#### <mark style="color:green;">What Are User Groups?</mark>

Groups are a way to sort user accounts logically and, in doing so, provide granular permissions and access to resources without having to manage each user manually. For example, we could restrict access to a specific directory or share so that only users who need access can view the files. On a singular host, this does not mean much to us. However, logical grouping is essential to maintain a proper security posture within a domain of hundreds, if not thousands, of users.&#x20;

**Get-LocalGroup**

{% code fullWidth="true" %}
```powershell
PS C:\htb> get-localgroup

Name                                Description
----                                -----------
__vmware__                          VMware User Group
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
Administrators                      Administrators have complete and unrestricted access to the computer/domain
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Device Owners                       Members of this group can change system-wide settings.
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
Event Log Readers                   Members of this group can read event logs from local machine
Guests                              Guests have the same access as members of the Users group by default, except for...
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
IIS_IUSRS                           Built-in group used by Internet Information Services.
Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
Performance Monitor Users           Members of this group can access performance counter data locally and remotely
Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
Replicator                          Supports file replication in a domain
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes an...  

```
{% endcode %}

***

### <mark style="color:blue;">Adding/Removing/Editing User Accounts & Groups</mark>

<mark style="color:green;">**Identifying Local Users**</mark>

```powershell
PS C:\htb> Get-LocalUser  
  
Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
DLarusso           True    High kick specialist.
Guest              False   Built-in account for guest access to the computer/domain
sshd               True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender A...
```

<mark style="color:green;">**Creating A New User**</mark>

```powershell
PS C:\htb>  New-LocalUser -Name "JLawrence" -NoPassword

Name      Enabled Description
----      ------- -----------
JLawrence True
```

If we wish to modify a user, we could use the `Set-LocalUser` cmdlet. For this example, we will modify `JLawrence` and set a password and description on his account.

<mark style="color:green;">**Modifying a User**</mark>

```powershell
PS C:\htb> $Password = Read-Host -AsSecureString
****************
PS C:\htb> Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"
PS C:\htb> Get-LocalUser  

Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
demo               True
Guest              False   Built-in account for guest access to the computer/domain
JLawrence          True    CEO EagleFang
```

<mark style="color:green;">**Get-LocalGroup**</mark>

User and Group Management

```powershell
PS C:\htb> Get-LocalGroup  

Name                                Description
----                                -----------
Access Control Assistance Operators Members of this group can remotely query authorization attr...
Administrators                      Administrators have complete and unrestricted access to the...
Backup Operators                    Backup Operators can override security restrictions for the...
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Device Owners                       Members of this group can change system-wide settings.
Distributed COM Users               Members are allowed to launch, activate and use Distributed...
Event Log Readers                   Members of this group can read event logs from local machine
Guests                              Guests have the same access as members of the Users group b...
Hyper-V Administrators              Members of this group have complete and unrestricted access...
IIS_IUSRS                           Built-in group used by Internet Information Services.
Network Configuration Operators     Members in this group can have some administrative privileg...
Performance Log Users               Members of this group may schedule logging of performance c...
Performance Monitor Users           Members of this group can access performance counter data l...
Power Users                         Power Users are included for backwards compatibility and po...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over managem...
Replicator                          Supports file replication in a domain
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional s...

PS C:\Windows\system32> Get-LocalGroupMember -Name "Users"

ObjectClass Name                             PrincipalSource
----------- ----                             ---------------
User        DESKTOP-B3MFM77\demo             Local
User        DESKTOP-B3MFM77\JLawrence        Local
Group       NT AUTHORITY\Authenticated Users Unknown
Group       NT AUTHORITY\INTERACTIVE         Unknown
```

<mark style="color:green;">**Adding a Member To a Group**</mark>

User and Group Management

```bash
PS C:\htb> Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"
PS C:\htb> Get-LocalGroupMember -Name "Remote Desktop Users" 

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        DESKTOP-B3MFM77\JLawrence Local
```

***

#### <mark style="color:green;">Managing Domain Users and Groups</mark>

**Installing RSAT**

```powershell
PS C:\htb> Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

Path          :  
Online        : True  
RestartNeeded : False  

```

The above command will install `ALL` RSAT features in the Microsoft Catalog. If we wish to stay lightweight, we can install the package named `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`. Now we should have the ActiveDirectory module installed. Let us check.

<mark style="color:green;">**Locating The AD Module**</mark>

```powershell
PS C:\htb> Get-Module -Name ActiveDirectory -ListAvailable 

    Directory: C:\Windows\system32\WindowsPowerShell\v1.0\Modules


ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAccount, Add-ADDomainControllerPasswordReplicationPolicy, Add-A...
```

Nice. Now that we have the module, we can get started with AD `User` and `Group` management. The easiest way to locate a specific user is by searching with the `Get-ADUser` cmdlet.

<mark style="color:green;">**Get-ADUser**</mark>

User and Group Management

```bash
PS C:\htb> Get-ADUser -Filter *

DistinguishedName : CN=user14,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         :
Name              : user14
ObjectClass       : user
ObjectGUID        : bef9787d-2716-4dc9-8e8f-f8037a72c3d9
SamAccountName    : user14
SID               : S-1-5-21-1480833693-1324064541-2711030367-1110
Surname           :
UserPrincipalName :

DistinguishedName : CN=sshd,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         :
Name              : sshd
ObjectClass       : user
ObjectGUID        : 7a324e98-00e4-480b-8a1a-fa465d558063
SamAccountName    : sshd
SID               : S-1-5-21-1480833693-1324064541-2711030367-1112
Surname           :
UserPrincipalName :

DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         :
Name              : TSilver
ObjectClass       : user
ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
SamAccountName    : TSilver
SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
Surname           :
UserPrincipalName :  

<SNIP>
```

<mark style="color:green;">**Get a Specific User**</mark>

```powershell
PS C:\htb>  Get-ADUser -Identity TSilver


DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         :
Name              : TSilver
ObjectClass       : user
ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
SamAccountName    : TSilver
SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
Surname           :
UserPrincipalName :
  
```

We can see from the output several pieces of information about the user, including:

* `Object Class`: which specifies if the object is a user, computer, or another type of object.
* `DistinguishedName`: Specifies the object's relative path within the AD schema.
* `Enabled`: Tells us if the user is active and can log in.
* `SamAccountName`: The representation of the username used to log into the ActiveDirectory hosts.
* `ObjectGUID`: Is the unique identifier of the user object.

Users have many different attributes ( not all shown here ) and can all be used to identify and group them. We could also use these to filter specific attributes. For example, let us filter the user's `Email address`.

<mark style="color:green;">**Searching On An Attribute**</mark>

```powershell
PS C:\htb> Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}


DistinguishedName : CN=TSilver,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         :
Name              : TSilver
ObjectClass       : user
ObjectGUID        : a19a6c8a-000a-4cbf-aa14-0c7fca643c37
SamAccountName    : TSilver
SID               : S-1-5-21-1480833693-1324064541-2711030367-1602
Surname           :
UserPrincipalName :
```

<mark style="color:green;">**New ADUser**</mark>

```powershell
PS C:\htb> New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true 

AccountPassword: ****************
PS C:\htb> Get-ADUser -Identity MTanaka -Properties * | Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail

Name    Enabled GivenName Surname Title  Office   Mail
----    ------- --------- ------- -----  ------   ----
MTanaka    True Mori      Tanaka  Sensei Security MTanaka@greenhorn.corp
```

Ok, a lot is going on here. It may look daunting but let us dissect it. The `first` portion of the output above is creating our user:

* `New-ADUser -Name "MTanaka"` : We issue the `New-ADUser` command and set the user's SamAccountName to `MTanaka`.
* `-Surname "Tanaka" -GivenName "Mori"`: This portion sets our user's `Lastname` and `Firstname`.
* `-Office "Security"`: Sets the extended property of `Office` to `Security`.
* `-OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"}`: Here we set other extended attributes such as `title` and `Email-Address`.
* `-Accountpassword (Read-Host -AsSecureString "AccountPassword")`: With this portion, we set the user's `password` by having the shell prompt us to enter a new password. (we can see it in the line below with the stars)
* `-Enabled $true`: We are enabling the account for use. The user could not log in if this was set to `\$False`.

The `second` is validating that the user we created and the properties we set exist:

* `Get-ADUser -Identity MTanaka -Properties *`: Here, we are searching for the user's properties `MTanaka`.
* `|` : This is the Pipe symbol. It will be explored more in another section, but for now, it takes our `output` from `Get-ADUser` and sends it into the following command.
* `Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail`: Here, we tell PowerShell to `Format` our results as a `table` including the default and extended properties listed.

Seeing the commands broken down like this helps demystify the strings. Now, what if we need to modify a user? `Set-ADUser` is our ticket. Many of the filters we looked at earlier apply here as well. We can change or set any of the attributes that were listed. For this example, let us add a `Description` to Mr. Tanaka.

<mark style="color:green;">**Changing a Users Attributes**</mark>

{% code fullWidth="true" %}
```powershell
PS C:\htb> Set-ADUser -Identity MTanaka -Description " Sensei to Security Analyst's Rocky, Colt, and Tum-Tum"  

PS C:\htb> Get-ADUser -Identity MTanaka -Property Description


Description       :  Sensei to Security Analyst's Rocky, Colt, and Tum-Tum
DistinguishedName : CN=MTanaka,CN=Users,DC=greenhorn,DC=corp
Enabled           : True
GivenName         : Mori
Name              : MTanaka
ObjectClass       : user
ObjectGUID        : c19e402d-b002-4ca0-b5ac-59d416166b3a
SamAccountName    : MTanaka
SID               : S-1-5-21-1480833693-1324064541-2711030367-1603
Surname           : Tanaka
UserPrincipalName :
```
{% endcode %}

***

### 🧾 User & Group Management – Tableau récapitulatif des commandes

#### 🔹 Utilisateurs locaux

| Commande                                                                           | Rôle                                |
| ---------------------------------------------------------------------------------- | ----------------------------------- |
| `Get-LocalUser`                                                                    | Lister tous les utilisateurs locaux |
| `New-LocalUser -Name "JLawrence" -NoPassword`                                      | Créer un utilisateur local          |
| `Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"` | Modifier un utilisateur local       |
| `Remove-LocalUser -Name "user"`                                                    | Supprimer un utilisateur local      |

***

#### 🔹 Groupes locaux

| Commande                                                                 | Rôle                               |
| ------------------------------------------------------------------------ | ---------------------------------- |
| `Get-LocalGroup`                                                         | Lister tous les groupes locaux     |
| `Get-LocalGroupMember -Name "Users"`                                     | Lister les membres d’un groupe     |
| `Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"` | Ajouter un utilisateur à un groupe |
| `Remove-LocalGroupMember -Group "Users" -Member "demo"`                  | Retirer un utilisateur d’un groupe |

***

#### 🔹 Modules PowerShell / RSAT

| Commande                                          | Rôle                               |
| ------------------------------------------------- | ---------------------------------- |
| `Get-Module`                                      | Voir les modules chargés           |
| `Get-Module -ListAvailable`                       | Voir tous les modules disponibles  |
| `Get-WindowsCapability -Name RSAT* -Online`       | Vérifier les capacités RSAT        |
| `Add-WindowsCapability -Online`                   | Installer RSAT                     |
| `Get-Module -Name ActiveDirectory -ListAvailable` | Vérifier le module ActiveDirectory |

***

#### 🔹 Utilisateurs Active Directory

| Commande                                             | Rôle                            |
| ---------------------------------------------------- | ------------------------------- |
| `Get-ADUser -Filter *`                               | Lister tous les utilisateurs AD |
| `Get-ADUser -Identity TSilver`                       | Afficher un utilisateur précis  |
| `Get-ADUser -Filter {EmailAddress -like '*corp'}`    | Rechercher par attribut         |
| `New-ADUser -Name "MTanaka" -Enabled $true`          | Créer un utilisateur AD         |
| `Set-ADUser -Identity MTanaka -Description "Sensei"` | Modifier un utilisateur AD      |
| `Get-ADUser -Identity MTanaka -Properties *`         | Voir tous les attributs         |

***

#### 🔹 Pipeline & affichage

| Élément                          | Rôle                       |
| -------------------------------- | -------------------------- |
| \`                               | \` (pipe)                  |
| `Format-Table`                   | Formater l’affichage       |
| `Format-Table Name,Enabled,Mail` | Afficher des champs précis |

***
