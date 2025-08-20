# Initial Enumeration

***

&#x20;[Windows commands reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)&#x20;

***

### <mark style="color:red;">System Information</mark>

<mark style="color:green;">**Tasklist**</mark>

* lister les processus en cours d'exécution sur un système, avec des détails tels que l'ID de processus (PID), l'image (nom du programme), l'utilisation de la mémoire

```cmd-session
C:\htb> tasklist /svc
```

{% hint style="warning" %}
<mark style="color:$success;">**Services**</mark>

* **Processus Windows standards** : Il est essentiel de connaître les processus Windows standards comme `smss.exe`, `csrss.exe`, `winlogon.exe`, `LSASS`, et `svchost.exe`, ainsi que les services associés.
* **Repérer les processus non standards** : Identifiez rapidement les processus/services standards pour mieux repérer les processus non standards, qui peuvent ouvrir des voies d'escalade de privilèges.
* **Exemple de processus intéressant** : Dans un cas d'exemple, un processus comme `FileZilla FTP server` peut être pertinent. Il est important de vérifier la version pour identifier des vulnérabilités publiques ou des mauvaises configurations (comme l'accès anonyme FTP).
* **Processus de sécurité** : Les processus comme `MsMpEng.exe` (Windows Defender) sont également importants car ils permettent de comprendre les protections en place, que nous devrons peut-être contourner.
{% endhint %}

<mark style="color:green;">**Display All Environment Variables**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> set
```
{% endcode %}

{% hint style="warning" %}
**Profils itinérants et risque de persistance** : Les répertoires de profil utilisateur, notamment `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup`, sont utilisés pour les profils itinérants (Roaming Profiles). Si un fichier malveillant y est placé, il sera exécuté lorsque l'utilisateur se connecte à une autre machine. Cela permettrait à un attaquant de maintenir l'accès ou de propager une attaque à travers plusieurs systèmes.
{% endhint %}

<mark style="color:green;">**View Detailed Configuration Information**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> systeminfo
```
{% endcode %}

<mark style="color:green;">**Patches and Updates**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> wmic qfe
```
{% endcode %}

<mark style="color:green;">**We can do this with PowerShell as well using the**</mark> [<mark style="color:green;">**Get-Hotfix**</mark>](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.1) <mark style="color:green;">**cmdlet.**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-HotFix | ft -AutoSize
```
{% endcode %}

<mark style="color:green;">**Installed Programs**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> wmic product get name
```
{% endcode %}

<mark style="color:green;">**We can, of course, do this with PowerShell as well using the**</mark> [<mark style="color:green;">**Get-WmiObject**</mark>](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) <mark style="color:green;">**cmdlet.**</mark>

{% code fullWidth="true" %}
```powershell-session
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version

```
{% endcode %}

<mark style="color:green;">**Display Running Processes**</mark>

```
tasklist
```

<mark style="color:green;">**Netstat**</mark>

```cmd-session
PS C:\htb> netstat -ano
```

***

### <mark style="color:red;">User & Group Information</mark>

* **Les utilisateurs comme le maillon faible** :
* **Comprendre les utilisateurs et groupes sur le système** :
* **Informations sur la politique de mot de passe** :
* **Vérifier les utilisateurs connectés** :
* **Cibles potentielles - Dossiers d'utilisateurs ou fichiers de mot de passe** :
* **Attention aux utilisateurs actifs** :

```cmd-session
C:\htb> query user
```

<mark style="color:green;">**Current User**</mark>

{% hint style="warning" %}
When we gain access to a host, we should always check what user context our account is running under first. Sometimes, we are already SYSTEM or equivalent! Suppose we gain access as a service account. In that case, we may have privileges such as `SeImpersonatePrivilege`, which can often be easily abused to escalate privileges using a tool such as [Juicy Potato](https://github.com/ohpe/juicy-potato).
{% endhint %}

```cmd-session
C:\htb> echo %USERNAME%
```

<mark style="color:green;">**Current User Privileges**</mark>

```cmd-session
C:\htb> whoami /priv
```

<mark style="color:green;">**Current User Group Information**</mark>

```cmd-session
C:\htb> whoami /groups
```

<mark style="color:green;">**Get All Users**</mark>

```cmd-session
C:\htb> net user
```

<mark style="color:green;">**Get All Groups**</mark>

```cmd-session
C:\htb> net localgroup
```

<mark style="color:green;">**Details About a Group**</mark>

We may find a password or other interesting information stored in the group's description.&#x20;

{% code fullWidth="true" %}
```cmd-session
C:\htb> net localgroup administrators
```
{% endcode %}

<mark style="color:green;">**Get Password Policy & Other Account Information**</mark>

```cmd-session
C:\htb> net accounts
```

***

{% hint style="info" %}
[h](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
{% endhint %}
