# Enumerating & Retrieving Password Policies

***

## <mark style="color:red;">Enumerating the Password Policy - from Linux - Credentialed</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
{% endcode %}

***

## <mark style="color:red;">Enumerating the Password Policy - from Linux - SMB NULL Sessions</mark>

{% hint style="warning" %}
The first is via an **SMB NULL session**. SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.&#x20;

**SMB NULL session misconfigurations** are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.

When creating a domain in earlier versions of Windows Server, anonymous access was granted to certain shares, which allowed for domain enumeration.
{% endhint %}

<mark style="color:green;">**Using rpcclient**</mark>

```shell-session
rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
```

<mark style="color:green;">**Obtaining the Password Policy using rpcclient**</mark>

```shell-session
rpcclient $> querydominfo
--------------------------

rpcclient $> getdompwinfo
```

***

Let's try this using [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux). `enum4linux` is a tool built around the [Samba suite of tools](https://www.samba.org/samba/docs/current/man-html/samba.7.html) `nmblookup`, `net`, `rpcclient` and `smbclient`

| Tool      | Ports                                             |
| --------- | ------------------------------------------------- |
| nmblookup | 137/UDP                                           |
| nbtstat   | 137/UDP                                           |
| net       | 139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535 |
| rpcclient | 135/TCP                                           |
| smbclient | 445/TCP                                           |

<mark style="color:green;">**Using enum4linux**</mark>

{% code fullWidth="true" %}
```shell-session
enum4linux -P 172.16.5.5
```
{% endcode %}

{% hint style="warning" %}
The tool [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) is a rewrite of `enum4linux` in Python, but has additional features such as the ability to export data as YAML or JSON files which can later be used to process the data further or feed it to other tools. It also supports colored output, among other features
{% endhint %}

<mark style="color:green;">**Using enum4linux-ng**</mark>

```shell-session
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

<mark style="color:green;">**Displaying the contents of ilfreight.json**</mark>

```shell-session
cat ilfreight.json 
```

***

## <mark style="color:red;">Enumerating Null Session - from Windows</mark>

We could use the command `net use \\host\ipc$ "" /u:""`&#x20;

<mark style="color:green;">**Establish a null session from windows**</mark>

```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.
```

We can also use a username/password combination to attempt to connect. Let's see some common errors when trying to authenticate:

<mark style="color:green;">**Error: Account is Disabled**</mark>

```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

<mark style="color:green;">**Error: Password is Incorrect**</mark>

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

<mark style="color:green;">**Error: Account is locked out (Password Policy)**</mark>

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

***

## <mark style="color:red;">Enumerating the Password Policy - from Linux - LDAP Anonymous Bind</mark>

{% hint style="warning" %}
[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.
{% endhint %}

With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc...&#x20;

<mark style="color:green;">**Using ldapsearch**</mark>

{% code overflow="wrap" fullWidth="true" %}
```shell-session
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
{% endcode %}

***

## <mark style="color:red;">Enumerating the Password Policy - from Windows</mark>

<mark style="color:green;">**Using net.exe**</mark>

```cmd-session
C:\htb> net accounts
```

Here we can glean the following information:

* Passwords never expire (Maximum password age set to Unlimited)
* The minimum password length is 8 so weak passwords are likely in use
* The lockout threshold is 5 wrong passwords
* Accounts remained locked out for 30 minutes

<mark style="color:green;">**Using PowerView**</mark>

{% code overflow="wrap" fullWidth="true" %}
```powershell-session
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```
{% endcode %}

PowerView gave us the same output as our `net accounts` command, just in a different format but also revealed that password complexity is enabled (`PasswordComplexity=1`).

***

## <mark style="color:red;">Analyzing the Password Policy</mark>

We've now pulled the password policy in numerous ways. Let's go through the policy for the INLANEFREIGHT.LOCAL domain piece by piece.

* **The minimum password length is 8** (8 is very common, but nowadays, we are seeing more and more organizations enforce a 10-14 character password, which can remove some password options for us, but does not mitigate the password spraying vector completely)
* The **account lockout threshold is 5** (it is not uncommon to see a lower threshold such as 3 or even no lockout threshold set at all)
* The **lockout duration is 30 minutes** (this may be higher or lower depending on the organization), so if we do accidentally lockout (avoid!!) an account, it will unlock after the 30-minute window passes
* **Accounts unlock automatically** (in some organizations, an admin must manually unlock the account). We never want to lockout accounts while performing password spraying, but we especially want to avoid locking out accounts in an organization where an admin would have to intervene and unlock hundreds (or thousands) of accounts by hand/script
* **Password complexity is enabled,** meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (`Password1` or `Welcome1` would satisfy the "complexity" requirement here, but are still clearly weak passwords).

The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |

***
