# Credentialed Enumeration - from Windows

***

### <mark style="color:red;">ActiveDirectory PowerShell Module</mark>

The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment from the command line.

<mark style="color:green;">**Discover Modules**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-Module
```
{% endcode %}

<mark style="color:green;">**Load ActiveDirectory Module**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```
{% endcode %}

#### <mark style="color:green;">Get Domain Info</mark>

```powershell-session
PS C:\htb> Get-ADDomain
```

This will print out helpful information like the domain SID, domain functional level, any child domains, and more.&#x20;

Next, we'll use the [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) cmdlet. We will be filtering for accounts with the `ServicePrincipalName` property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack, which we will cover in-depth after the next section.

<mark style="color:green;">**Get-ADUser**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
{% endcode %}

<mark style="color:green;">**Checking For Trust Relationships**</mark>

```powershell-session
PS C:\htb> Get-ADTrust -Filter *
```

{% hint style="warning" %}
This cmdlet will print out any trust relationships the domain has. We can determine if they are trusts within our forest or with domains in other forests, the type of trust, the direction of the trust, and the name of the domain the relationship is with. This will be useful later on when looking to take advantage of child-to-parent trust relationships and attacking across forest trusts.&#x20;
{% endhint %}

<mark style="color:green;">**Group Enumeration**</mark>

```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name
```

We can take the results and feed interesting names back into the cmdlet to get more detailed information about a particular group like so:

<mark style="color:green;">**Detailed Group Info**</mark>

```powershell-session
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```

Now that we know more about the group, let's get a member listing using the [Get-ADGroupMember](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2022-ps) cmdlet.

#### <mark style="color:green;">Group Membership</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```
{% endcode %}

***

### <mark style="color:red;">PowerView</mark>

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us gain situational awareness within an AD environment.&#x20;

<table data-header-hidden data-full-width="true"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td><strong>Command</strong></td><td><strong>Description</strong></td></tr><tr><td><code>Export-PowerViewCSV</code></td><td>Append results to a CSV file</td></tr><tr><td><code>ConvertTo-SID</code></td><td>Convert a User or group name to its SID value</td></tr><tr><td><code>Get-DomainSPNTicket</code></td><td>Requests the Kerberos ticket for a specified Service Principal Name (SPN) account</td></tr><tr><td><strong>Domain/LDAP Functions:</strong></td><td></td></tr><tr><td><code>Get-Domain</code></td><td>Will return the AD object for the current (or specified) domain</td></tr><tr><td><code>Get-DomainController</code></td><td>Return a list of the Domain Controllers for the specified domain</td></tr><tr><td><code>Get-DomainUser</code></td><td>Will return all users or specific user objects in AD</td></tr><tr><td><code>Get-DomainComputer</code></td><td>Will return all computers or specific computer objects in AD</td></tr><tr><td><code>Get-DomainGroup</code></td><td>Will return all groups or specific group objects in AD</td></tr><tr><td><code>Get-DomainOU</code></td><td>Search for all or specific OU objects in AD</td></tr><tr><td><code>Find-InterestingDomainAcl</code></td><td>Finds object ACLs in the domain with modification rights set to non-built in objects</td></tr><tr><td><code>Get-DomainGroupMember</code></td><td>Will return the members of a specific domain group</td></tr><tr><td><code>Get-DomainFileServer</code></td><td>Returns a list of servers likely functioning as file servers</td></tr><tr><td><code>Get-DomainDFSShare</code></td><td>Returns a list of all distributed file systems for the current (or specified) domain</td></tr><tr><td><strong>GPO Functions:</strong></td><td></td></tr><tr><td><code>Get-DomainGPO</code></td><td>Will return all GPOs or specific GPO objects in AD</td></tr><tr><td><code>Get-DomainPolicy</code></td><td>Returns the default domain policy or the domain controller policy for the current domain</td></tr><tr><td><strong>Computer Enumeration Functions:</strong></td><td></td></tr><tr><td><code>Get-NetLocalGroup</code></td><td>Enumerates local groups on the local or a remote machine</td></tr><tr><td><code>Get-NetLocalGroupMember</code></td><td>Enumerates members of a specific local group</td></tr><tr><td><code>Get-NetShare</code></td><td>Returns open shares on the local (or a remote) machine</td></tr><tr><td><code>Get-NetSession</code></td><td>Will return session information for the local (or a remote) machine</td></tr><tr><td><code>Test-AdminAccess</code></td><td>Tests if the current user has administrative access to the local (or a remote) machine</td></tr><tr><td><strong>Threaded 'Meta'-Functions:</strong></td><td></td></tr><tr><td><code>Find-DomainUserLocation</code></td><td>Finds machines where specific users are logged in</td></tr><tr><td><code>Find-DomainShare</code></td><td>Finds reachable shares on domain machines</td></tr><tr><td><code>Find-InterestingDomainShareFile</code></td><td>Searches for files matching specific criteria on readable shares in the domain</td></tr><tr><td><code>Find-LocalAdminAccess</code></td><td>Find machines on the local domain where the current user has local administrator access</td></tr><tr><td><strong>Domain Trust Functions:</strong></td><td></td></tr><tr><td><code>Get-DomainTrust</code></td><td>Returns domain trusts for the current domain or a specified domain</td></tr><tr><td><code>Get-ForestTrust</code></td><td>Returns all forest trusts for the current forest or a specified forest</td></tr><tr><td><code>Get-DomainForeignUser</code></td><td>Enumerates users who are in groups outside of the user's domain</td></tr><tr><td><code>Get-DomainForeignGroupMember</code></td><td>Enumerates groups with users outside of the group's domain and returns each foreign member</td></tr><tr><td><code>Get-DomainTrustMapping</code></td><td>Will enumerate all trusts for the current domain and any others seen.</td></tr></tbody></table>

{% hint style="warning" %}
For more on PowerView, check out the [Active Directory PowerView module](https://academy.hackthebox.com/course/preview/active-directory-powerview). Below we will experiment with a few of them.
{% endhint %}

<mark style="color:green;">**Domain User Information**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```
{% endcode %}

<mark style="color:green;">**Recursive Group Membership**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb>  Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
{% endcode %}

Above we performed a recursive look at the `Domain Admins` group to list its members. Now we know who to target for potential elevation of privileges. Like with the AD PowerShell module, we can also enumerate domain trust mappings.

<mark style="color:green;">**Trust Enumeration**</mark>

```powershell-session
PS C:\htb> Get-DomainTrustMapping
```

We can use the [Test-AdminAccess](https://powersploit.readthedocs.io/en/latest/Recon/Test-AdminAccess/) function to test for local admin access on either the current machine or a remote one.

<mark style="color:green;">**Testing for Local Admin Access**</mark>

```powershell-session
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

<mark style="color:green;">**Finding Users With SPN Set**</mark>

```powershell-session
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

***

### <mark style="color:red;">SharpView</mark>

{% hint style="warning" %}
The BC-SECURITY version of [PowerView](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/situational_awareness/network/powerview.ps1) has some new functions such as `Get-NetGmsa`, used to hunt for [Group Managed Service Accounts](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview), which is out of scope for this module.&#x20;
{% endhint %}

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Help
```
{% endcode %}

Here we can use SharpView to enumerate information about a specific user, such as the user `forend`, which we control.

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend
```
{% endcode %}

***

### <mark style="color:red;">Snaffler</mark>

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.

<mark style="color:green;">**Snaffler Execution**</mark>

```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

The `-s` tells it to print results to the console for us, the `-d` specifies the domain to search within, and the `-o` tells Snaffler to write results to a logfile. The `-v` option is the verbosity level. Typically `data` is best as it only displays results to the screen, so it's easier to begin looking through the tool runs. Snaffler can produce a considerable amount of data, so we should typically output to file and let it run and then come back to it later. It can also be helpful to provide Snaffler raw output to clients as supplemental data during a penetration test as it can help them zero in on high-value shares that should be locked down first.

<mark style="color:green;">**Snaffler in Action**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> .\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```
{% endcode %}

We may find passwords, SSH keys, configuration files, or other data that can be used to further our access. Snaffler color codes the output for us and provides us with a rundown of the file types found in the shares.

***

## <mark style="color:red;">BloodHound</mark>

If we run SharpHound with the `--help` option, we can see the options available to us.

<mark style="color:green;">**SharpHound in Action**</mark>

```powershell-session
PS C:\htb>  .\SharpHound.exe --help
```

We'll start by running the SharpHound.exe collector from the MS01 attack host.

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```
{% endcode %}

Nous pouvons commencer par taper `domain:` dans la barre de recherche en haut à gauche et choisir **INLANEFREIGHT.LOCAL** parmi les résultats. Prenons un moment pour parcourir l'onglet **Node Info**. Comme nous pouvons le voir, cela correspondrait à une entreprise assez grande avec plus de 550 hôtes à cibler et des relations de confiance avec deux autres domaines.

Maintenant, examinons quelques requêtes pré-construites dans l'onglet **Analysis**. La requête **Find Computers with Unsupported Operating Systems** est idéale pour trouver des systèmes d'exploitation obsolètes et non pris en charge qui exécutent des logiciels hérités. Ces systèmes sont relativement courants dans les réseaux d'entreprise (en particulier dans les environnements plus anciens), car ils exécutent souvent des produits qui ne peuvent pas encore être mis à jour ou remplacés. Garder ces hôtes peut permettre d'économiser de l'argent, mais cela peut aussi ajouter des vulnérabilités inutiles au réseau. Les hôtes plus anciens peuvent être vulnérables à des failles d'exécution de code à distance anciennes, comme MS08-067. Si nous rencontrons ces hôtes plus anciens pendant une évaluation, nous devons être prudents avant de les attaquer (ou même vérifier avec notre client) car ils peuvent être fragiles et exécuter des applications ou des services critiques. Nous pouvons conseiller à notre client de segmenter ces hôtes du reste du réseau autant que possible s'ils ne peuvent pas les retirer encore, mais nous devrions aussi recommander qu'ils commencent à élaborer un plan pour les mettre hors service et les remplacer.

Cette requête montre deux hôtes, l'un exécutant Windows 7 et l'autre exécutant Windows Server 2008 (aucun des deux n'est "actif" dans notre laboratoire). Parfois, nous verrons des hôtes qui ne sont plus allumés mais qui apparaissent encore comme des enregistrements dans Active Directory (AD). Nous devons toujours valider s'ils sont "actifs" ou non avant de faire des recommandations dans nos rapports. Nous pourrions rédiger une constatation à haut risque pour les systèmes d'exploitation hérités ou une recommandation de bonnes pratiques pour nettoyer les anciens enregistrements dans AD.

**Unsupported Operating Systems**

<figure><img src="../../.gitbook/assets/unsupported.webp" alt=""><figcaption></figcaption></figure>

Nous verrons souvent des utilisateurs ayant des droits d'administrateur local sur leur hôte (peut-être temporairement pour installer un logiciel, et ces droits n'ont jamais été supprimés), ou bien ils occupent un rôle suffisamment élevé dans l'organisation pour justifier ces droits (qu'ils en aient besoin ou non). D'autres fois, nous verrons des droits d'administrateur local excessifs attribués à travers l'organisation, comme plusieurs groupes dans le département informatique ayant des droits d'administrateur local sur des groupes de serveurs ou même le groupe **Domain Users** ayant des droits d'administrateur local sur un ou plusieurs hôtes. Cela peut nous être utile si nous prenons le contrôle d'un compte utilisateur ayant ces droits sur une ou plusieurs machines. Nous pouvons exécuter la requête **Find Computers where Domain Users are Local Admin** pour voir rapidement s'il existe des hôtes où tous les utilisateurs ont des droits d'administrateur local. Si tel est le cas, alors tout compte que nous contrôlons pourra généralement être utilisé pour accéder aux hôtes en question, et nous pourrons peut-être récupérer des identifiants depuis la mémoire ou trouver d'autres données sensibles.

***

We have a great picture of the domain's layout, strengths, and weaknesses. We have credentials for several users and have enumerated a wealth of information such as users, groups, computers, GPOs, ACLs, local admin rights, access rights (RDP, WinRM, etc.), accounts configured with Service Principal Names (SPNs), and more.&#x20;
